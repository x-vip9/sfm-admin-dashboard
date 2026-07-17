'use strict';
require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const path       = require('path');
const fs         = require('fs');
const multer     = require('multer');
const crypto     = require('crypto');

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET  || 'sfm_secret_key_2024_very_long';
if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'sfm_secret_key_2024_very_long') {
    // مفتاح افتراضي معروف بالكود المصدري نفسه — تشغيله بالإنتاج بدون تغييره
    // يكسر أمان الجلسات بالكامل (أي حد يقدر يزوّر توكن دخول لأي حساب مدير)
    console.error('❌ FATAL: JWT_SECRET is not set (or still the default value) in production. Refusing to start for security reasons. Set a strong random JWT_SECRET in your environment variables.');
    process.exit(1);
}
const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'Admin@2024';
if (process.env.NODE_ENV === 'production' && ADMIN_PASS === 'Admin@2024') {
    // نفس منطق الحماية المطبّق على JWT_SECRET أعلاه — كلمة مرور افتراضية
    // معروفة بالكود المصدري نفسه تعني أي شخص يقدر يخمّنها ويدخل كمدير كامل
    console.error('❌ FATAL: ADMIN_PASSWORD is not set (or still the default value) in production. Refusing to start for security reasons. Set a strong ADMIN_PASSWORD in your environment variables.');
    process.exit(1);
}
const CLIENT_KEY = process.env.CLIENT_API_KEY || 'sfm-client-key-2024';
if (process.env.NODE_ENV === 'production' && CLIENT_KEY === 'sfm-client-key-2024') {
    // نفس منطق الحماية المطبّق على JWT_SECRET وADMIN_PASSWORD — هذا المفتاح
    // يحمي كل روابط /client/* (إصدار تراخيص، رفع تذاكر، تسجيل نشاط...).
    // كان بلا أي حماية إطلاقاً رغم كونه بنفس خطورة المفتاحين الآخرين —
    // معروف بالكود المصدري نفسه، فأي شخص يقدر يستدعي هذي الروابط مباشرة
    console.error('❌ FATAL: CLIENT_API_KEY is not set (or still the default value) in production. Refusing to start for security reasons. Set a strong CLIENT_API_KEY in your environment variables (and update it in the desktop app and Softora config to match).');
    process.exit(1);
}
// للاتصال بموقع Softora وجلب قائمة مستخدميه (لتعبئة نموذج الترخيص تلقائياً) —
// لازم تضبط نفس قيمة ADMIN_SECRET المضبوطة بمتغيرات بيئة موقع Softora هنا بالضبط
const SOFTORA_URL = (process.env.SOFTORA_URL || 'https://softora-website.onrender.com').replace(/\/+$/,'');
const SOFTORA_ADMIN_KEY = process.env.SOFTORA_ADMIN_KEY || '';

// نُبلّغ موقع Softora فور أي تغيير على منتج أو شريك حتى ينعكس مباشرة بدل
// انتظار انتهاء صلاحية الكاش عندهم (كانت تصل 20 ثانية). لا ننتظر رد هذا
// الاستدعاء (fire-and-forget) — فشله المؤقت ما يوقف عملية المدير، وأسوأ
// حالة يرجع الكاش يحدّث نفسه تلقائياً بعد 20 ثانية بأي حال (خط دفاع ثانٍ
// موجود أصلاً بجانب هذا التحديث الفوري).
// نستخدم CLIENT_KEY نفسه (مو SOFTORA_ADMIN_KEY) لأنه سر مشترك أصلاً بين
// الطرفين لحماية روابط /client/* بالاتجاه المعاكس — ما نحتاج سر إضافي منفصل
function notifySoftoraChanged(kind) {
    fetch(`${SOFTORA_URL}/api/${kind}/invalidate-cache`, {
        method: 'POST',
        headers: { 'x-api-key': CLIENT_KEY },
    }).catch(() => {});
}
function notifySoftoraProductsChanged() { notifySoftoraChanged('products'); }
function notifySoftoraPartnersChanged() { notifySoftoraChanged('partners'); }

// ── ملفات تثبيت المنتجات وشعارات الشركاء تُخزَّن الآن بشكل دائم داخل
// MongoDB نفسها عبر GridFS (راجع db.js) — بدل القرص المحلي المؤقت السابق
// الذي كان يُمسح بكل عملية نشر جديدة على Render (نفس مشكلة data.json
// الأصلية بالضبط، قبل الانتقال لـ MongoDB) ──

// ── تخزين الملفات: GridFS داخل MongoDB (راجع db.js) — دائم، لا يتأثر
// بإعادة النشر، بدل القرص المحلي المؤقت السابق. multer الآن يستقبل الملف
// كبفر بالذاكرة (memoryStorage) بدل كتابته على القرص، ثم نرفعه لـ GridFS
// يدوياً داخل كل مسار — هذا يسمح لنا نتحقق من صحة المنتج/الشريك ونحذف
// الملف القديم من GridFS *قبل* ما نكمل الرفع
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 500 * 1024 * 1024 }, // 500 ميغابايت كحد أقصى لكل ملف
    fileFilter: (req, file, cb) => {
        // نسمح فقط بامتدادات ملفات التثبيت الشائعة — يمنع رفع أي نوع ملف عشوائي بالغلط
        const allowed = /\.(exe|msi|dmg|pkg|zip|AppImage)$/i;
        if (!allowed.test(file.originalname)) return cb(new Error('صيغة ملف غير مدعومة — الصيغ المسموحة: exe, msi, dmg, pkg, zip, AppImage'));
        cb(null, true);
    },
});

const uploadLogo = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 ميغابايت كحد أقصى — شعار مش برنامج
    fileFilter: (req, file, cb) => {
        const allowed = /\.(png|jpe?g|svg|webp)$/i;
        if (!allowed.test(file.originalname)) return cb(new Error('صيغة صورة غير مدعومة — الصيغ المسموحة: png, jpg, svg, webp'));
        cb(null, true);
    },
});

// ── البيانات الآن دائمة عبر MongoDB Atlas بدل data.json على القرص ──
// (القرص عند Render بالخطة المجانية "مؤقت" ويُمسح بكل إعادة نشر — راجع db.js)
const dbModule = require('./db');
const { loadDB, saveDB } = dbModule;

function nextId(arr) {
    return arr.length > 0 ? Math.max(...arr.map(r=>r.id||0))+1 : 1;
}
function logAdminActivity(db, adminUsername, action, details) {
    if (!db.admin_activity) db.admin_activity = [];
    db.admin_activity.push({
        id: nextId(db.admin_activity),
        admin: adminUsername || 'system',
        action, details: details || '',
        created_at: new Date().toISOString()
    });
    if (db.admin_activity.length > 2000) db.admin_activity = db.admin_activity.slice(-2000);
}

// ── رؤوس أمان HTTP (Helmet) — كانت مثبَّتة كمكتبة لكن غير مُفعَّلة إطلاقاً.
// CSP هنا يسمح بـ unsafe-inline لأن لوحة التحكم تستخدم onclick="" و style=""
// inline بكثرة بكل الصفحة — تعطيلها يكسر كل زر وتنسيق باللوحة. تحسين
// مستقبلي: إعادة بناء التعامل مع الأحداث بدون سمات inline لسياسة أشد.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://fonts.googleapis.com'],
            styleSrcAttr: ["'unsafe-inline'"],
            fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdn.jsdelivr.net'],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'", 'https://cdn.jsdelivr.net'],
        },
    },
}));
// ── CORS مقيَّد — لوحة التحكم نفسها من نفس الأصل (same-origin) دائماً
// مسموحة تلقائياً (المتصفح يرسل ترويسة Origin حتى بطلبات نفس الموقع
// لأي POST/PATCH/DELETE، فلازم نتحقق من التطابق الفعلي مع مضيف الطلب
// نفسه، لا رفض كل Origin غير مُدرَج مسبقاً — هذا كان يكسر حتى تسجيل
// الدخول من اللوحة نفسها). أي أصل خارجي إضافي فعلي يُضاف صراحةً عبر
// متغيّر بيئة ALLOWED_ORIGINS (مفصول بفواصل).
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors((req, callback) => {
    const origin = req.headers.origin;
    let allow = true; // لا ترويسة Origin إطلاقاً = طلب من سطر أوامر/سيرفر لسيرفر، مسموح دائماً
    if (origin) {
        let sameOrigin = false;
        try { sameOrigin = new URL(origin).host === req.headers.host; } catch (e) {}
        allow = sameOrigin || ALLOWED_ORIGINS.includes(origin);
    }
    callback(null, { origin: allow });
}));
app.use(express.json({limit:'1mb'}));
// ── حد معدّل عام لكل روابط API — طبقة حماية إضافية فوق قفل محاولات
// الدخول الموجود أصلاً (LOGIN_MAX_ATTEMPTS)، يمنع أي إساءة استخدام آلية
// لأي رابط API آخر (مثلاً استنزاف موارد الخادم بطلبات متكررة سريعة)
const apiLimiter = rateLimit({windowMs:15*60*1000, max:300, standardHeaders:true, legacyHeaders:false,
    message: {error:'طلبات كثيرة جداً، حاول لاحقاً'}});
// حد أعلى لروابط /client/* تحديداً — حركتها مجمّعة من خادم Softora نفسه
// نيابة عن كل مستخدميه (عنوان IP واحد لعدد كبير من العمليات الفعلية)،
// فحد 300 المخصص لزائر واحد يكون ضيقاً جداً عليها وقت الذروة
const clientLimiter = rateLimit({windowMs:15*60*1000, max:2000, standardHeaders:true, legacyHeaders:false,
    message: {error:'طلبات كثيرة جداً، حاول لاحقاً'}});
app.use('/api/', apiLimiter);
app.use('/client/', clientLimiter);
app.use(express.static(path.join(__dirname,'public')));

// ═══════════════════════════════════════════════════════════════════
// نظام صلاحيات متدرّج (RBAC):
// - Owner: مدير واحد أعلى (الحساب المزروع تلقائياً أول تشغيل) — كل
//   الصلاحيات دائماً بلا قيود، ولا يقدر أي أحد غيره تعديل حسابه أو
//   انتحال دوره. هو الوحيد اللي يقدر يدير حسابات المشرفين والنسخ
//   الاحتياطي (أخطر قسمين بالنظام).
// - Admin (مشرف): حساب يضيفه الـ Owner بصلاحيات محدودة على محورين:
//   1. product_scope: 'all' أو مصفوفة معرّفات منتجات — يحدد أي منتج
//      يقدر المشرف يشوف/يدير تراخيصه ومدفوعاته وبياناته.
//   2. sections: لكل قسم بلوحة التحكم قيمة من ثلاث: 'none' (بلا صلاحية
//      إطلاقاً، القسم لا يظهر له)، 'view' (مشاهدة فقط)، أو 'manage'
//      (إضافة/تعديل/حذف كامل).
// ═══════════════════════════════════════════════════════════════════
const SECTIONS = ['users','files','activity','tickets','commands','notifications','products','partners','licenses','payments','updates','website_activity','pricing_plans','site_maintenance'];
function defaultSections(level) {
    const s = {}; SECTIONS.forEach(k => s[k] = level); return s;
}
function auth(req,res,next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({error:'غير مصرح'});
    let payload;
    try { payload = jwt.verify(token,JWT_SECRET); }
    catch(e) { return res.status(401).json({error:'جلسة منتهية'}); }
    // نجلب السجل الحي لحساب المدير من قاعدة البيانات في كل طلب (لا نثق
    // بالصلاحيات المخزَّنة داخل التوكن القديم) — أي تعديل صلاحية يسويه
    // الـ Owner ينعكس فوراً بالطلب التالي، بدون الحاجة لتسجيل خروج ودخول
    const db = loadDB();
    ensureOwnerExists(db); // شبكة أمان إضافية: يضمن وجود Owner دائماً بغض النظر عن أي مسار وصلنا له
    const admin = (db.admins||[]).find(a => a.id === payload.id);
    if (!admin) return res.status(401).json({error:'الحساب غير موجود'});
    req.admin = { id: admin.id, username: admin.username, role: admin.role, permissions: admin.permissions || null };
    next();
}
// الـ Owner فقط — لإدارة حسابات المشرفين والنسخ الاحتياطي، أخطر قسمين بالنظام
function requireOwner(req,res,next) {
    if (req.admin?.role !== 'owner') return res.status(403).json({error:'هذا الإجراء متاح لصاحب الحساب الرئيسي (Owner) فقط'});
    next();
}
// يتحقق من صلاحية المشرف على قسم معيّن بمستوى معيّن (مشاهدة أو إدارة).
// الـ Owner يتجاوز هذا التحقق دائماً بلا قيود
function sectionAccess(section, level) {
    return (req,res,next) => {
        if (req.admin?.role === 'owner') return next();
        const perm = req.admin?.permissions?.sections?.[section] || 'none';
        if (perm === 'none') return res.status(403).json({error:'ليس لديك صلاحية للوصول لهذا القسم'});
        if (level === 'manage' && perm !== 'manage') return res.status(403).json({error:'ليس لديك صلاحية للتعديل بهذا القسم — مشاهدة فقط'});
        next();
    };
}
// يصفّي أي مصفوفة سجلات (تراخيص/منتجات/مدفوعات) حسب نطاق المنتج المسموح
// للمشرف الحالي — الـ Owner يشوف الكل دائماً بلا تصفية
function filterByProductScope(req, items, productIdField='product_id') {
    if (req.admin?.role === 'owner') return items;
    const scope = req.admin?.permissions?.product_scope;
    if (!scope || scope === 'all') return items;
    return items.filter(it => scope.includes(it[productIdField]));
}
function inProductScope(req, productId) {
    if (req.admin?.role === 'owner') return true;
    const scope = req.admin?.permissions?.product_scope;
    return !scope || scope === 'all' || scope.includes(productId);
}
// مقارنة نصوص بزمن ثابت — تمنع هجمات "قياس الوقت" (timing attack) اللي
// يقدر فيها مهاجم يخمّن مفتاحاً سرياً حرفاً بحرف عن طريق قياس فرق أزمنة
// استجابة السيرفر بالميلي ثانية
function timingSafeEqual(a, b) {
    const bufA = Buffer.from(String(a ?? ''));
    const bufB = Buffer.from(String(b ?? ''));
    if (bufA.length !== bufB.length) {
        crypto.timingSafeEqual(bufA, Buffer.alloc(bufA.length)); // نقارن بزمن مشابه حتى لو الطول مختلف
        return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
}
function clientAuth(req,res,next) {
    if (!timingSafeEqual(req.headers['x-api-key'], CLIENT_KEY)) return res.status(401).json({error:'Unauthorized'});
    next();
}

// إنشاء حساب المدير الأساسي أول مرة فقط (ترحيل من متغيرات البيئة القديمة)
// — هذا الحساب هو الـ Owner دائماً، بلا أي قيود
function ensureSeedAdmin(db) {
    if (!db.admins) db.admins = [];
    if (db.admins.length === 0) {
        db.admins.push({
            id: 1, username: ADMIN_USER,
            password_hash: bcrypt.hashSync(ADMIN_PASS, 10),
            role: 'owner', permissions: null, created_at: new Date().toISOString()
        });
        saveDB(db);
    }
    ensureAdminPermissionsMigrated(db);
}
// يضمن دائماً وجود Owner واحد بالضبط بين حسابات المشرفين — يُنفَّذ في كل
// طلب (وليس مرة واحدة فقط عبر علم ترحيل)، حتى يُصلح نفسه تلقائياً لو حدث
// أي خلل سابق تسبب بعدم تعيين أي حساب كـ Owner (كما حدث فعلياً هنا)
function ensureOwnerExists(db) {
    if (!db.admins || !db.admins.length) return;
    if (db.admins.some(a => a.role === 'owner')) return;
    const sorted = db.admins.slice().sort((a,b) => (a.id||0) - (b.id||0));
    sorted[0].role = 'owner';
    sorted[0].permissions = null;
    saveDB(db);
}
// ترحيل لمرة واحدة: النظام القديم كان يميّز فقط بين 'admin' (كل الصلاحيات)
// و'viewer' (مشاهدة فقط بكل شي). النظام الجديد يحتاج Owner واحد + مشرفين
// بصلاحيات مفصّلة لكل قسم ولكل منتج. نحافظ على نفس مستوى الوصول الحالي
// تماماً لكل حساب موجود مسبقاً حتى لا ينقطع عمل أي أحد فجأة بعد التحديث:
// أول حساب (الأقدم) يصير Owner، والباقي 'admin' بصلاحيات كاملة إن كان
// دوره القديم 'admin'، أو صلاحيات مشاهدة فقط إن كان دوره القديم 'viewer'.
function ensureAdminPermissionsMigrated(db) {
    ensureOwnerExists(db);
    if (db.admins_permissions_migrated) return;
    if (!db.admins || !db.admins.length) return;
    const sorted = db.admins.slice().sort((a,b) => (a.id||0) - (b.id||0));
    sorted.forEach((a, idx) => {
        if (idx === 0) { a.role = 'owner'; a.permissions = null; return; }
        const wasFullAdmin = a.role !== 'viewer';
        a.role = 'admin';
        a.permissions = { product_scope: 'all', sections: defaultSections(wasFullAdmin ? 'manage' : 'view') };
    });
    db.admins_permissions_migrated = true;
    saveDB(db);
}

// ── إدارة المنتجات: المدير هو من يضيف كل منتج يدويًا من لوحة التحكم —
// لا يُزرع أي منتج تلقائيًا بعد الآن. الدالة أدناه أصبحت تقتصر على ترحيل
// التراخيص القديمة (من قبل نظام تعدد المنتجات) التي لا تملك product_id،
// حتى تبقى مرتبطة بمعرّف 'sfm' القديم بدل أن تُفقد من أي تصفية بالمنتج —
// هذا لا يُنشئ أي منتج، فقط يضبط حقلاً بسجلات تراخيص قديمة إن وُجدت.
function ensureSeedProduct(db) {
    if (!db.products) db.products = [];
    if (!db.products_seeded) {
        (db.licenses||[]).forEach(l => { if (!l.product_id) l.product_id = 'sfm'; });
        db.products_seeded = true;
        saveDB(db);
    }
}

// خطط الأسعار كانت قبل هذا التحديث أرقاماً ثابتة مكتوبة مباشرة بكود موقع
// Softora (غير قابلة للتعديل إلا برفع كود جديد). نزرعها هنا تلقائياً بنفس
// القيم بالضبط أول مرة يُستدعى فيها أي مسار متعلق بالأسعار، حتى لا ينكسر
// شيء لحظة نشر هذا التحديث — الموقع يستمر يعرض نفس الأسعار والمميزات
// السابقة تماماً، لكن الآن قابلة للتعديل من هذي اللوحة مباشرة
function ensureSeedPricingPlans(db) {
    if (!db.pricing_plans) db.pricing_plans = [];
    if (db.pricing_plans_seeded) return;
    db.pricing_plans_seeded = true;
    if (db.pricing_plans.some(p => p.product_id === 'sfm')) { saveDB(db); return; }
    const now = new Date().toISOString();
    db.pricing_plans.push(
        {
            id: 'starter', product_id: 'sfm', name: 'الأساسية', name_en: 'Starter',
            desc: 'للمشاريع الصغيرة والناشئة', desc_en: 'For small and startup projects',
            price_monthly: 99, price_yearly: 990, discount_percent: 0, max_devices: 1,
            popular: false, active: true, order: 1, created_at: now,
            features: [
                {text:'جهاز واحد', text_en:'1 Device', included:true},
                {text:'تشفير AES-256 للملفات', text_en:'AES-256 file encryption', included:true},
                {text:'قفل وحماية الملفات الحساسة', text_en:'Lock and protect sensitive files', included:true},
                {text:'سجل نشاط أساسي', text_en:'Basic activity log', included:true},
                {text:'دعم عبر البريد', text_en:'Email support', included:true},
                {text:'نسخ احتياطي سحابي', text_en:'Cloud backup', included:false},
            ],
        },
        {
            id: 'business', product_id: 'sfm', name: 'الأعمال', name_en: 'Business',
            desc: 'للشركات المتوسطة والمتنامية', desc_en: 'For medium and growing businesses',
            price_monthly: 299, price_yearly: 2990, discount_percent: 0, max_devices: 5,
            popular: true, active: true, order: 2, created_at: now,
            features: [
                {text:'حتى 5 أجهزة', text_en:'Up to 5 devices', included:true},
                {text:'كل ميزات الباقة الأساسية', text_en:'Everything in Starter', included:true},
                {text:'نسخ احتياطي سحابي', text_en:'Cloud backup', included:true},
                {text:'سلة محذوفات آمنة', text_en:'Secure recycle bin', included:true},
                {text:'دعم أولوية', text_en:'Priority support', included:true},
                {text:'مدير حساب مخصص', text_en:'Dedicated account manager', included:false},
            ],
        },
        {
            id: 'enterprise', product_id: 'sfm', name: 'المؤسسات', name_en: 'Enterprise',
            desc: 'للشركات الكبيرة والمؤسسات', desc_en: 'For large companies and institutions',
            price_monthly: 1150, price_yearly: 11500, discount_percent: 0, max_devices: 999,
            popular: false, active: true, order: 3, created_at: now,
            features: [
                {text:'أجهزة غير محدودة', text_en:'Unlimited devices', included:true},
                {text:'كل ميزات باقة الأعمال', text_en:'Everything in Business', included:true},
                {text:'تقارير نشاط تفصيلية', text_en:'Detailed activity reports', included:true},
                {text:'دعم أولوية 24/7', text_en:'24/7 Priority support', included:true},
                {text:'مدير حساب مخصص', text_en:'Dedicated account manager', included:true},
            ],
        },
    );
    saveDB(db);
}

function slugify(s) {
    return String(s||'').trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'') || ('p'+Date.now());
}
// نفس منطق التطبيع بالواجهة الأمامية بالضبط — دفاع بعمق: حتى لو تجاوز أحد
// التحقق الأمامي (استدعاء API مباشر)، الخادم لا يثق بأي مدخل من العميل
// ويطبّق نفس القاعدة بنفسه دائماً
function normalizeUrl(u) {
    u = String(u||'').trim();
    if (!u) return '';
    if (/^https?:\/\//i.test(u)) return u;
    return 'https://' + u.replace(/^\/+/, '');
}

// ── إدارة المنتجات (كل برنامج/موقع تبنيه يُضاف هنا مرة واحدة، وتصير التراخيص متاحة له فوراً) ──
app.get('/api/products', auth, sectionAccess('products','view'), (req,res) => {
    const db = loadDB(); ensureSeedProduct(db);
    res.json(filterByProductScope(req, db.products, 'id'));
});
// نقطة قراءة عامة للمنتجات النشطة فقط — تستخدمها مواقع مثل Softora لعرض الكتالوج
app.get('/client/products', clientAuth, (req,res) => {
    const db = loadDB(); ensureSeedProduct(db);
    res.json(db.products.filter(p=>p.active).map(p=>({id:p.id,name:p.name,name_en:p.name_en||'',slug:p.slug,description:p.description,description_en:p.description_en||'',icon:p.icon,platform:p.platform,version:p.version||'',url:p.url||'',has_file:!!p.file_name,file_size:p.file_size||0,app_store_url:p.app_store_url||'',play_store_url:p.play_store_url||''})));
});
app.post('/api/products', auth, sectionAccess('products','manage'), (req,res) => {
    const {name, name_en, description, description_en, icon, platform, code, version, url, app_store_url, play_store_url} = req.body;
    if (!name) return res.status(400).json({error:'اسم المنتج مطلوب'});
    const normalizedUrl = normalizeUrl(url);
    const db = loadDB(); ensureSeedProduct(db);
    let id = slugify(code || name);
    if (db.products.find(p=>p.id===id)) id = id + '-' + Date.now().toString(36);
    const product = {id, name, name_en:name_en||'', slug:id, description:description||'', description_en:description_en||'', icon:icon||'📦', platform:platform||'desktop', version:version||'', url:normalizedUrl, app_store_url: app_store_url?normalizeUrl(app_store_url):'', play_store_url: play_store_url?normalizeUrl(play_store_url):'', active:true, created_at:new Date().toISOString()};
    db.products.push(product);
    logAdminActivity(db, req.admin.username, 'create_product', `${product.name} (${product.id})`);
    saveDB(db);
    notifySoftoraProductsChanged();
    res.json({ok:true, product});
});
app.patch('/api/products/:id', auth, sectionAccess('products','manage'), (req,res) => {
    const db = loadDB(); ensureSeedProduct(db);
    const p = db.products.find(p=>p.id===req.params.id);
    if (!p) return res.status(404).json({error:'غير موجود'});
    if (!inProductScope(req, p.id)) return res.status(403).json({error:'هذا المنتج خارج نطاق صلاحيتك'});
    const {name, name_en, description, description_en, icon, platform, active, version, url, app_store_url, play_store_url} = req.body;
    if (name!==undefined) p.name = name;
    if (name_en!==undefined) p.name_en = name_en;
    if (description!==undefined) p.description = description;
    if (description_en!==undefined) p.description_en = description_en;
    if (icon!==undefined) p.icon = icon;
    if (platform!==undefined) p.platform = platform;
    if (version!==undefined) p.version = version;
    if (url!==undefined) p.url = normalizeUrl(url);
    if (app_store_url!==undefined) p.app_store_url = app_store_url ? normalizeUrl(app_store_url) : '';
    if (play_store_url!==undefined) p.play_store_url = play_store_url ? normalizeUrl(play_store_url) : '';
    if (active!==undefined) p.active = !!active;
    logAdminActivity(db, req.admin.username, 'edit_product', `${p.name} (${p.id})`);
    saveDB(db);
    notifySoftoraProductsChanged();
    res.json({ok:true});
});
app.delete('/api/products/:id', auth, sectionAccess('products','manage'), (req,res) => {
    const db = loadDB(); ensureSeedProduct(db);
    if (!inProductScope(req, req.params.id)) return res.status(403).json({error:'هذا المنتج خارج نطاق صلاحيتك'});
    const inUse = (db.licenses||[]).some(l => l.product_id === req.params.id && l.status !== 'cancelled');
    if (inUse) return res.status(400).json({error:'لا يمكن حذف منتج له تراخيص فعّالة — ألغِ التراخيص أولاً أو عطّل المنتج بدل حذفه'});
    const p = db.products.find(p=>p.id===req.params.id);
    if (p?.file_name) dbModule.deleteFile(p.file_name).catch(()=>{});
    db.products = db.products.filter(p=>p.id!==req.params.id);
    if (p) logAdminActivity(db, req.admin.username, 'delete_product', `${p.name} (${p.id})`);
    saveDB(db);
    notifySoftoraProductsChanged();
    res.json({ok:true});
});

// ── رفع ملف تثبيت لبرنامج سطح مكتب — يُستدعى من نموذج المنتج بلوحة التحكم ──
app.post('/api/products/:id/file', auth, sectionAccess('products','manage'), (req,res) => {
    // نتحقق من وجود المنتج *قبل* تشغيل multer — لو نفّذنا الرفع أولاً، اسم
    // الملف يُبنى من req.params.id مباشرة (قيمة يتحكم بها الطالب بالكامل عبر
    // الرابط)، وأي تحقق لاحق بعد الكتابة يكون متأخراً جداً
    const db = loadDB(); ensureSeedProduct(db);
    const product = db.products.find(p=>p.id===req.params.id);
    if (!product) return res.status(404).json({error:'المنتج غير موجود'});
    // تحقق إضافي دفاعي: معرّفات المنتجات تُبنى دايماً عبر slugify() (أحرف
    // إنجليزية صغيرة وأرقام وشرطات فقط) — أي شي غير مطابق لهذا النمط مرفوض
    // فوراً بغض النظر عن أي شي ثاني، كطبقة حماية مستقلة عن التحقق أعلاه
    if (!/^[a-z0-9-]+$/.test(req.params.id)) return res.status(400).json({error:'معرّف منتج غير صالح'});
    if (!inProductScope(req, product.id)) return res.status(403).json({error:'هذا المنتج خارج نطاق صلاحيتك'});

    upload.single('file')(req, res, async (err) => {
        if (err) return res.status(400).json({error: err.message || 'فشل رفع الملف'});
        if (!req.file) return res.status(400).json({error:'لم يُرفَع أي ملف'});
        try {
            const db2 = loadDB(); ensureSeedProduct(db2);
            const p = db2.products.find(p=>p.id===req.params.id);
            if (!p) return res.status(404).json({error:'المنتج غير موجود'});
            const oldFileId = p.file_name;
            // نرفع الملف الجديد لـ GridFS (تخزين دائم داخل MongoDB) أولاً،
            // ثم نحذف القديم بعد نجاح الرفع — يمنع فقدان الملف القديم لو
            // فشل رفع الجديد لأي سبب بمنتصف الطريق
            const fileId = await dbModule.uploadFile(req.file.buffer, req.file.originalname, req.file.mimetype);
            if (oldFileId) dbModule.deleteFile(oldFileId).catch(()=>{});
            p.file_name = fileId;
            p.file_original_name = req.file.originalname;
            p.file_size = req.file.size;
            p.file_uploaded_at = new Date().toISOString();
            logAdminActivity(db2, req.admin.username, 'upload_product_file', `${p.name} — ${req.file.originalname} (${(req.file.size/1024/1024).toFixed(1)}MB)`);
            saveDB(db2);
            notifySoftoraProductsChanged();
            res.json({ok:true, file_name:req.file.originalname, size:req.file.size});
        } catch(e) { res.status(500).json({error:'فشل حفظ الملف: '+e.message}); }
    });
});

app.delete('/api/products/:id/file', auth, sectionAccess('products','manage'), (req,res) => {
    const db = loadDB(); ensureSeedProduct(db);
    const p = db.products.find(p=>p.id===req.params.id);
    if (!p) return res.status(404).json({error:'المنتج غير موجود'});
    if (!inProductScope(req, p.id)) return res.status(403).json({error:'هذا المنتج خارج نطاق صلاحيتك'});
    if (p.file_name) dbModule.deleteFile(p.file_name).catch(()=>{});
    p.file_name = null; p.file_original_name = null; p.file_size = null; p.file_uploaded_at = null;
    logAdminActivity(db, req.admin.username, 'delete_product_file', p.name);
    saveDB(db);
    notifySoftoraProductsChanged();
    res.json({ok:true});
});

// ══════════════ إدارة "شركاؤنا" — يظهرون بموقع Softora ══════════════
app.get('/api/partners', auth, sectionAccess('partners','view'), (req,res) => {
    const db = loadDB();
    res.json((db.partners||[]).sort((a,b)=>(a.order||0)-(b.order||0)));
});
app.post('/api/partners', auth, sectionAccess('partners','manage'), (req,res) => {
    const {name, name_en, website_url} = req.body;
    if (!name) return res.status(400).json({error:'اسم الشريك مطلوب'});
    const normalizedUrl = normalizeUrl(website_url);
    const db = loadDB();
    if (!db.partners) db.partners = [];
    const id = 'p' + Date.now().toString(36) + Math.random().toString(36).slice(2,6);
    const maxOrder = db.partners.reduce((m,p)=>Math.max(m,p.order||0), 0);
    const partner = {id, name, name_en:name_en||'', website_url:normalizedUrl, logo_name:null, active:true, order:maxOrder+1, created_at:new Date().toISOString()};
    db.partners.push(partner);
    logAdminActivity(db, req.admin.username, 'create_partner', partner.name);
    saveDB(db);
    notifySoftoraPartnersChanged();
    res.json({ok:true, partner});
});
app.patch('/api/partners/:id', auth, sectionAccess('partners','manage'), (req,res) => {
    const db = loadDB();
    const p = (db.partners||[]).find(p=>p.id===req.params.id);
    if (!p) return res.status(404).json({error:'غير موجود'});
    const {name, name_en, website_url, active, order} = req.body;
    if (website_url!==undefined) p.website_url = normalizeUrl(website_url);
    if (name!==undefined) p.name = name;
    if (name_en!==undefined) p.name_en = name_en;
    if (active!==undefined) p.active = !!active;
    if (order!==undefined) p.order = Number(order)||0;
    logAdminActivity(db, req.admin.username, 'edit_partner', p.name);
    saveDB(db);
    notifySoftoraPartnersChanged();
    res.json({ok:true});
});
app.delete('/api/partners/:id', auth, sectionAccess('partners','manage'), (req,res) => {
    const db = loadDB();
    const p = (db.partners||[]).find(p=>p.id===req.params.id);
    if (!p) return res.status(404).json({error:'غير موجود'});
    if (p.logo_name) dbModule.deleteFile(p.logo_name).catch(()=>{});
    db.partners = db.partners.filter(x=>x.id!==req.params.id);
    logAdminActivity(db, req.admin.username, 'delete_partner', p.name);
    saveDB(db);
    notifySoftoraPartnersChanged();
    res.json({ok:true});
});
app.post('/api/partners/:id/logo', auth, sectionAccess('partners','manage'), (req,res) => {
    // نفس منطق الحماية المطبَّق على رفع ملفات المنتجات بالضبط — نتحقق من
    // وجود الشريك ونصادق شكل المعرّف *قبل* تشغيل multer، يمنع اجتياز مسار
    const db = loadDB();
    const partner = (db.partners||[]).find(p=>p.id===req.params.id);
    if (!partner) return res.status(404).json({error:'الشريك غير موجود'});
    if (!/^[a-z0-9]+$/.test(req.params.id)) return res.status(400).json({error:'معرّف غير صالح'});

    uploadLogo.single('logo')(req, res, async (err) => {
        if (err) return res.status(400).json({error: err.message || 'فشل رفع الشعار'});
        if (!req.file) return res.status(400).json({error:'لم يُرفَع أي ملف'});
        try {
            const db2 = loadDB();
            const p = (db2.partners||[]).find(p=>p.id===req.params.id);
            if (!p) return res.status(404).json({error:'الشريك غير موجود'});
            const oldFileId = p.logo_name;
            const fileId = await dbModule.uploadFile(req.file.buffer, req.file.originalname, req.file.mimetype);
            if (oldFileId) dbModule.deleteFile(oldFileId).catch(()=>{});
            p.logo_name = fileId;
            logAdminActivity(db2, req.admin.username, 'upload_partner_logo', p.name);
            saveDB(db2);
            notifySoftoraPartnersChanged();
            res.json({ok:true});
        } catch(e) { res.status(500).json({error:'فشل حفظ الشعار: '+e.message}); }
    });
});
// نقطة قراءة عامة للشركاء النشطين فقط — يستخدمها موقع Softora
app.get('/client/partners', clientAuth, (req,res) => {
    const db = loadDB();
    res.json((db.partners||[]).filter(p=>p.active).sort((a,b)=>(a.order||0)-(b.order||0))
        .map(p=>({id:p.id, name:p.name, name_en:p.name_en||'', website_url:p.website_url||'', has_logo:!!p.logo_name})));
});
app.get('/client/partners/:id/logo', clientAuth, async (req,res) => {
    const db = loadDB();
    const p = (db.partners||[]).find(p=>p.id===req.params.id);
    if (!p || !p.logo_name) return res.status(404).json({error:'لا يوجد شعار لهذا الشريك'});
    try { await dbModule.streamFileTo(p.logo_name, res); }
    catch(e) { if (!res.headersSent) res.status(404).json({error:'الملف غير موجود'}); }
});
// نسخة عامة بدون مصادقة لعرض الشعار داخل لوحة التحكم نفسها (وسم <img> ما
// يقدر يرسل هيدر Authorization) — شعار شركة أصلاً محتوى عام مصيره الظهور
// على الموقع بأي حال، فما فيه داعٍ لحمايته بمصادقة هنا
app.get('/api/partners/:id/logo', async (req,res) => {
    const db = loadDB();
    const p = (db.partners||[]).find(p=>p.id===req.params.id);
    if (!p || !p.logo_name) return res.status(404).json({error:'لا يوجد شعار'});
    try { await dbModule.streamFileTo(p.logo_name, res); }
    catch(e) { if (!res.headersSent) res.status(404).json({error:'الملف غير موجود'}); }
});

// ── تحميل ملف المنتج — يستدعيه موقع Softora نيابة عن المستخدم (وسيط/proxy)
// بعد ما يتحقق هو من صلاحية اشتراك المستخدم بنفسه أولاً؛ هذا الرابط نفسه
// محمي بمفتاح العميل فقط (نفس حماية بقية روابط /client/*) ──
app.get('/client/products/:id/file', clientAuth, async (req,res) => {
    const db = loadDB(); ensureSeedProduct(db);
    const p = db.products.find(p=>p.id===req.params.id);
    if (!p || !p.file_name) return res.status(404).json({error:'لا يوجد ملف مرفوع لهذا المنتج'});
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(p.file_original_name || p.file_name)}"`);
    try { await dbModule.streamFileTo(p.file_name, res); }
    catch(e) { if (!res.headersSent) res.status(404).json({error:'الملف غير موجود على الخادم'}); }
});


// حماية بسيطة من محاولات الدخول المتكررة — قفل مؤقت بعد 5 محاولات فاشلة
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_MS = 10 * 60 * 1000; // 10 دقائق
function getClientIp(req) { return (req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown').trim(); }

// ── Admin Auth ──
app.post('/api/auth/login', (req,res) => {
    const {username,password} = req.body;
    const db = loadDB();
    ensureSeedAdmin(db);
    const ip = getClientIp(req);
    if (!db.login_attempts) db.login_attempts = {};
    const attempt = db.login_attempts[ip];
    if (attempt && attempt.lockedUntil && attempt.lockedUntil > Date.now()) {
        const mins = Math.ceil((attempt.lockedUntil - Date.now())/60000);
        return res.status(429).json({error:`محاولات كثيرة فاشلة — حاول بعد ${mins} دقيقة`});
    }
    const adminAcc = db.admins.find(a=>a.username===username);
    const valid = adminAcc && bcrypt.compareSync(password||'', adminAcc.password_hash);
    if (!valid) {
        const a = db.login_attempts[ip] || {count:0, lockedUntil:0};
        a.count = (a.count||0) + 1;
        if (a.count >= LOGIN_MAX_ATTEMPTS) { a.lockedUntil = Date.now() + LOGIN_LOCK_MS; a.count = 0; }
        db.login_attempts[ip] = a;
        saveDB(db);
        return res.status(401).json({error:'بيانات غير صحيحة'});
    }
    delete db.login_attempts[ip];
    logAdminActivity(db, adminAcc.username, 'login', 'تسجيل دخول ناجح');
    saveDB(db);
    const token = jwt.sign({username: adminAcc.username, role: adminAcc.role, id: adminAcc.id},JWT_SECRET,{expiresIn:'24h'});
    res.json({ok:true,token,username:adminAcc.username,role:adminAcc.role});
});

app.get('/api/auth/me', auth, (req,res) => {
    res.json({id:req.admin.id, username:req.admin.username, role:req.admin.role, permissions:req.admin.permissions});
});

// ── إدارة حسابات المشرفين (Owner فقط) ──
// الحساب صاحب النظام (Owner) واحد ثابت دائماً بكل الصلاحيات — أي حساب
// يُنشأ من هنا هو "مشرف" (staff) بصلاحيات محدودة يحددها الـ Owner: أي
// منتج/موقع يقدر يشوفه (product_scope)، وما مستوى صلاحيته داخل كل قسم
// بلوحة التحكم على حدة (sections: 'none' | 'view' | 'manage')
app.get('/api/admins', auth, requireOwner, (req,res) => {
    const db = loadDB(); ensureSeedAdmin(db);
    res.json(db.admins.map(a=>({id:a.id, username:a.username, role:a.role, permissions:a.permissions, created_at:a.created_at})));
});
// يتحقق من صيغة كائن الصلاحيات المُرسَل من الواجهة، ويرفض أي قسم أو
// مستوى غير معروف بدل قبوله بصمت — يمنع تسلل قيم غير متوقعة لقاعدة البيانات
function validatePermissions(body) {
    const scope = body.product_scope;
    if (scope !== 'all' && !Array.isArray(scope)) return {error:'نطاق المنتج غير صالح'};
    const sections = body.sections || {};
    const cleanSections = {};
    for (const key of SECTIONS) {
        const level = sections[key] || 'none';
        if (!['none','view','manage'].includes(level)) return {error:`مستوى صلاحية غير صالح للقسم: ${key}`};
        cleanSections[key] = level;
    }
    return {ok:true, permissions: {product_scope: scope, sections: cleanSections}};
}
app.post('/api/admins', auth, requireOwner, (req,res) => {
    const {username, password} = req.body;
    if (!username || username.length<3) return res.status(400).json({error:'اسم المستخدم 3 أحرف على الأقل'});
    if (!password || password.length<8) return res.status(400).json({error:'كلمة المرور 8 أحرف على الأقل'});
    const v = validatePermissions(req.body);
    if (v.error) return res.status(400).json({error:v.error});
    const db = loadDB();
    if (db.admins.find(a=>a.username===username)) return res.status(400).json({error:'اسم المستخدم مستخدم مسبقاً'});
    const newAdmin = {id: nextId(db.admins), username, password_hash: bcrypt.hashSync(password,10), role:'admin', permissions:v.permissions, created_at: new Date().toISOString()};
    db.admins.push(newAdmin);
    logAdminActivity(db, req.admin.username, 'create_admin', `إنشاء حساب مشرف: ${username}`);
    saveDB(db);
    res.json({ok:true});
});
// تعديل صلاحيات مشرف موجود — لم يكن موجوداً سابقاً (كان ممكن فقط إنشاء
// الحساب بصلاحيات ثابتة أول مرة بلا أي طريقة لتعديلها لاحقاً)
app.patch('/api/admins/:id', auth, requireOwner, (req,res) => {
    const db = loadDB();
    const id = parseInt(req.params.id);
    const target = db.admins.find(a=>a.id===id);
    if (!target) return res.status(404).json({error:'غير موجود'});
    if (target.role==='owner') return res.status(400).json({error:'لا يمكن تعديل صلاحيات صاحب الحساب الرئيسي'});
    const v = validatePermissions(req.body);
    if (v.error) return res.status(400).json({error:v.error});
    target.permissions = v.permissions;
    logAdminActivity(db, req.admin.username, 'edit_admin_permissions', `تعديل صلاحيات: ${target.username}`);
    saveDB(db);
    res.json({ok:true});
});
app.delete('/api/admins/:id', auth, requireOwner, (req,res) => {
    const db = loadDB();
    const id = parseInt(req.params.id);
    const target = db.admins.find(a=>a.id===id);
    if (!target) return res.status(404).json({error:'غير موجود'});
    if (target.role==='owner') return res.status(400).json({error:'لا يمكن حذف صاحب الحساب الرئيسي'});
    db.admins = db.admins.filter(a=>a.id!==id);
    logAdminActivity(db, req.admin.username, 'delete_admin', `حذف حساب مشرف: ${target.username}`);
    saveDB(db);
    res.json({ok:true});
});
app.patch('/api/admins/:id/password', auth, (req,res) => {
    const db = loadDB();
    const id = parseInt(req.params.id);
    const target = db.admins.find(a=>a.id===id);
    if (!target) return res.status(404).json({error:'غير موجود'});
    // فقط الـ Owner أو صاحب الحساب نفسه يقدر يغيّر كلمة المرور
    if (req.admin.role!=='owner' && req.admin.username!==target.username) return res.status(403).json({error:'غير مصرح'});
    const {password} = req.body;
    if (!password || password.length<8) return res.status(400).json({error:'كلمة المرور 8 أحرف على الأقل'});
    target.password_hash = bcrypt.hashSync(password,10);
    logAdminActivity(db, req.admin.username, 'change_admin_password', `تغيير كلمة مرور: ${target.username}`);
    saveDB(db);
    res.json({ok:true});
});
// ── "حسابي" — أي مشرف (بما فيه الـ Owner) يقدر يعدّل بياناته الشخصية
// (اسم المستخدم حالياً) بنفسه، بدون حاجة لصلاحية Owner أو الوصول لصفحة
// إدارة المشرفين المقصورة عليه ──
app.patch('/api/admins/me', auth, (req,res) => {
    const db = loadDB();
    const me = db.admins.find(a => a.id === req.admin.id);
    if (!me) return res.status(404).json({error:'الحساب غير موجود'});
    const {username} = req.body;
    if (username !== undefined) {
        const trimmed = String(username).trim();
        if (!trimmed || trimmed.length<3) return res.status(400).json({error:'اسم المستخدم 3 أحرف على الأقل'});
        if (db.admins.find(a => a.id !== me.id && a.username === trimmed)) return res.status(400).json({error:'اسم المستخدم مستخدم مسبقاً'});
        const oldUsername = me.username;
        me.username = trimmed;
        logAdminActivity(db, oldUsername, 'update_own_account', `تغيير اسم المستخدم إلى: ${trimmed}`);
    }
    saveDB(db);
    res.json({ok:true, username: me.username});
});

// ── سجل نشاط المشرفين (Audit Log) — يعرض إجراءات المشرفين البشريين
// المُضافين فقط. مستثنى عمداً: إجراءات صاحب الحساب الرئيسي (Owner)، وأي
// أحداث نظامية تلقائية (مثل "softora-payment" الذي يصدر تراخيص آلياً بعد
// نجاح الدفع بدون أي تدخل بشري) — الهدف هنا مراقبة المشرفين تحديداً، لا
// أي حدث آخر يُسجَّل بنفس الجدول لأغراض تدقيق مختلفة ──
app.get('/api/admin-activity', auth, requireOwner, (req,res) => {
    const db = loadDB();
    const staffUsernames = new Set((db.admins||[]).filter(a => a.role !== 'owner').map(a => a.username));
    const staffOnly = (db.admin_activity||[]).filter(a => staffUsernames.has(a.admin));
    res.json(staffOnly.slice().reverse());
});

// ── النسخ الاحتياطي (الآن مخزّن داخل MongoDB — دائم ولا يتأثر بإعادة النشر) ──
app.get('/api/backup/list', auth, requireOwner, async (req,res) => {
    try { res.json(await dbModule.listBackups()); }
    catch(e) { res.json([]); }
});
app.post('/api/backup/create', auth, requireOwner, async (req,res) => {
    try {
        const filename = await dbModule.createBackupRecord('backup');
        const db = loadDB();
        logAdminActivity(db, req.admin.username, 'create_backup', filename);
        saveDB(db);
        res.json({ok:true, filename});
    } catch(e) { res.status(500).json({error:'فشل إنشاء النسخة الاحتياطية'}); }
});
app.get('/api/backup/download/:filename?', auth, requireOwner, async (req,res) => {
    try {
        const filename = req.params.filename;
        if (filename && !/^[\w.:-]+\.json$/.test(filename)) return res.status(400).json({error:'اسم ملف غير صالح'});
        const payload = filename ? (await dbModule.getBackupByName(filename))?.data : loadDB();
        if (!payload) return res.status(404).json({error:'الملف غير موجود'});
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="${filename || 'sfm-data-backup.json'}"`);
        res.send(JSON.stringify(payload, null, 2));
    } catch(e) { res.status(500).json({error:'فشل التحميل'}); }
});
app.delete('/api/backup/:filename', auth, requireOwner, async (req,res) => {
    try {
        const filename = req.params.filename;
        if (!/^backup-[\w.:-]+\.json$/.test(filename)) return res.status(400).json({error:'اسم ملف غير صالح'});
        const deleted = await dbModule.deleteBackupByName(filename);
        if (!deleted) return res.status(404).json({error:'النسخة غير موجودة'});
        const db = loadDB();
        logAdminActivity(db, req.admin.username, 'delete_backup', filename);
        saveDB(db);
        res.json({ok:true});
    } catch(e) { res.status(500).json({error:'فشل حذف النسخة'}); }
});
app.post('/api/backup/restore/:filename', auth, requireOwner, async (req,res) => {
    try {
        if (!/^[\w.:-]+\.json$/.test(req.params.filename)) return res.status(400).json({error:'اسم ملف غير صالح'});
        const ok = await dbModule.restoreFromBackup(req.params.filename);
        if (!ok) return res.status(404).json({error:'النسخة غير موجودة'});
        const db = loadDB();
        logAdminActivity(db, req.admin.username, 'restore_backup', req.params.filename);
        saveDB(db);
        res.json({ok:true});
    } catch(e) { res.status(500).json({error:'فشلت الاستعادة'}); }
});

// ── Stats ──
// جلب مستخدمي موقع Softora — يُستخدم بنموذج إنشاء الترخيص لتعبئة البريد
// والاسم تلقائياً لعملاء سجّلوا بالموقع (مو بس مستخدمي البرنامج المحلي).
// نمرّر الطلب من طرف السيرفر حتى يبقى مفتاح SOFTORA_ADMIN_KEY سرّياً ولا
// يظهر أبداً بكود الواجهة اللي يشوفه المتصفح
app.get('/api/softora-users', auth, async (req,res) => {
    if (!SOFTORA_ADMIN_KEY) return res.json([]); // غير مُفعّل — نرجع قائمة فاضية بهدوء بدل خطأ يعطّل الصفحة
    try {
        const r = await fetch(`${SOFTORA_URL}/api/auth/admin/users`, {
            headers: { 'x-admin-secret': SOFTORA_ADMIN_KEY },
        });
        if (!r.ok) return res.json([]);
        const data = await r.json();
        res.json(Array.isArray(data) ? data : []);
    } catch(e) { res.json([]); }
});
// حذف مستخدم موقع — وسيط (proxy) لنقطة الحذف الموجودة أصلاً بموقع Softora،
// بنفس مفتاح SOFTORA_ADMIN_KEY المستخدم أعلاه لجلب القائمة
app.delete('/api/softora-users', auth, sectionAccess('users','manage'), async (req,res) => {
    if (!SOFTORA_ADMIN_KEY) return res.status(503).json({error:'هذي الميزة تحتاج ضبط SOFTORA_ADMIN_KEY أولاً'});
    const {email} = req.body;
    if (!email) return res.status(400).json({error:'البريد الإلكتروني مطلوب'});
    try {
        const r = await fetch(`${SOFTORA_URL}/api/auth/admin/user`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json', 'x-admin-secret': SOFTORA_ADMIN_KEY },
            body: JSON.stringify({email}),
        });
        const d = await r.json();
        if (!r.ok) return res.status(r.status).json(d);
        const db = loadDB();
        logAdminActivity(db, req.admin.username, 'delete_website_user', email);
        saveDB(db);
        res.json(d);
    } catch(e) { res.status(502).json({error:'تعذّر الاتصال بموقع Softora'}); }
});

app.get('/api/stats', auth, (req,res) => {
    const db = loadDB();
    const actMap={};
    db.activity.forEach(a=>{actMap[a.type||'أخرى']=(actMap[a.type||'أخرى']||0)+1;});
    const activity_by_type=Object.entries(actMap).map(([type,c])=>({type,c})).sort((a,b)=>b.c-a.c).slice(0,6);
    const fileMap={};
    db.files.forEach(f=>{const t=f.type||'أخرى';fileMap[t]=(fileMap[t]||0)+1;});
    const files_by_type=Object.entries(fileMap).map(([type,c])=>({type,c})).sort((a,b)=>b.c-a.c).slice(0,6);
    const soon = new Date(); soon.setDate(soon.getDate()+7);
    const expiringSoon = db.licenses.filter(l => l.plan!=='lifetime' && !l.cancelled && l.expires_at && new Date(l.expires_at) >= new Date() && new Date(l.expires_at) <= soon);
    // اتجاه آخر 7 أيام لكل مقياس له معنى زمني حقيقي (لعرضه كرسم مصغّر
    // "sparkline" داخل بطاقة الإحصائية بلوحة التحكم الرئيسية) — الأرقام
    // مرتبة من الأقدم للأحدث
    function last7DayCounts(items, dateField) {
        const days = [];
        for (let i=6; i>=0; i--) {
            const d = new Date(); d.setDate(d.getDate()-i);
            days.push(d.toISOString().slice(0,10));
        }
        const counts = Object.fromEntries(days.map(d=>[d,0]));
        items.forEach(it => {
            const d = (it[dateField]||'').slice(0,10);
            if (d in counts) counts[d]++;
        });
        return days.map(d=>counts[d]);
    }
    const trends = {
        users: last7DayCounts(db.users, 'created_at'),
        payments: last7DayCounts(db.payments||[], 'paid_at'),
        tickets: last7DayCounts(db.tickets, 'created_at'),
        files: last7DayCounts(db.files, 'created_at'),
    };
    res.json({
        users:db.users.length, tickets:db.tickets.filter(t=>t.status==='open').length,
        open_tickets:db.tickets.filter(t=>t.status==='open').length,
        active_users:db.users.filter(u=>(u.status||'active')==='active').length,
        files:db.files.length, storage:db.files.reduce((s,f)=>s+(f.size||0),0),
        total_size:db.files.reduce((s,f)=>s+(f.size||0),0),
        activity_today:db.activity.filter(a=>a.created_at?.startsWith(new Date().toISOString().slice(0,10))).length,
        notifications:db.notifications.filter(n=>!n.read).length,
        commands_pending:db.commands.filter(c=>c.status==='pending').length,
        recent_users:db.users.slice(-5).reverse(),
        recent_tickets:db.tickets.filter(t=>t.status==='open').slice(-5).reverse(),
        activity_by_type, files_by_type, trends,
        licenses_expiring_soon: expiringSoon.length,
        expiring_licenses: expiringSoon.map(l=>({key:l.key,email:l.email,name:l.name,expires_at:l.expires_at,plan:l.plan})),
        products: (db.products||[]).length,
        admins: (db.admins||[]).length,
        payments: (db.payments||[]).length,
        payments_total: (db.payments||[]).reduce((s,p)=>s+(p.amount||0),0),
    });
});

// ── Users ──
app.get('/api/users', auth, sectionAccess('users','view'), (req,res) => res.json(loadDB().users));
app.post('/api/users/create', auth, sectionAccess('users','manage'), (req,res) => {
    const {username,password,role='user'} = req.body;
    if (!username) return res.status(400).json({error:'Missing username'});
    const db=loadDB();
    if (db.users.find(u=>u.username===username)) return res.status(400).json({error:'اسم المستخدم مستخدم مسبقاً'});
    const finalRole = username==='admin' ? 'admin' : role;
    db.users.push({id:'usr_'+Date.now(),username,role:finalRole,status:'active',files_count:0,storage_used:0,created_at:new Date().toISOString()});
    logAdminActivity(db, req.admin.username, 'create_user', `إنشاء مستخدم: ${username}`);
    saveDB(db); res.json({ok:true});
});
app.patch('/api/users/:id/role', auth, sectionAccess('users','manage'), (req,res) => {
    const db=loadDB(); const u=db.users.find(u=>u.id===req.params.id);
    if (!u) return res.status(404).json({error:'Not found'});
    if (u.username==='admin') return res.status(400).json({error:'لا يمكن تغيير صلاحية حساب مدير النظام'});
    u.role=req.body.role;
    logAdminActivity(db, req.admin.username, 'change_user_role', `${u.username} → ${req.body.role}`);
    saveDB(db); res.json({ok:true});
});
app.patch('/api/users/:id', auth, sectionAccess('users','manage'), (req,res) => {
    const db=loadDB(); const u=db.users.find(u=>u.id===req.params.id);
    if (!u) return res.status(404).json({error:'Not found'});
    const {name,email,max_devices} = req.body;
    if (name!==undefined)  u.name=name;
    if (email!==undefined) {
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'بريد إلكتروني غير صالح'});
        u.email=email;
    }
    if (max_devices!==undefined) {
        const md=parseInt(max_devices);
        if (!Number.isInteger(md) || md<1) return res.status(400).json({error:'عدد الأجهزة يجب أن يكون رقماً صحيحاً 1 أو أكثر'});
        u.max_devices=md;
    }
    logAdminActivity(db, req.admin.username, 'edit_user', `تعديل بيانات: ${u.username}`);
    saveDB(db); res.json({ok:true});
});
const USER_STATUSES=['active','suspended','disabled'];
app.patch('/api/users/:id/status', auth, sectionAccess('users','manage'), (req,res) => {
    const db=loadDB(); const u=db.users.find(u=>u.id===req.params.id);
    if (!u) return res.status(404).json({error:'Not found'});
    if (u.username==='admin') return res.status(400).json({error:'لا يمكن تعطيل حساب مدير النظام'});
    const requested = req.body && req.body.status;
    u.status = USER_STATUSES.includes(requested) ? requested : (u.status==='active'?'disabled':'active');
    logAdminActivity(db, req.admin.username, 'change_user_status', `${u.username} → ${u.status}`);
    saveDB(db); res.json({ok:true,status:u.status});
});
app.delete('/api/users/:id', auth, sectionAccess('users','manage'), (req,res) => {
    const db=loadDB();
    const u = db.users.find(u=>u.id===req.params.id);
    db.users=db.users.filter(u=>u.id!==req.params.id);
    db.files=db.files.filter(f=>f.user_id!==req.params.id);
    logAdminActivity(db, req.admin.username, 'delete_user', `حذف مستخدم: ${u?.username||req.params.id}`);
    saveDB(db); res.json({ok:true});
});

// ── Tickets ──
app.get('/api/tickets', auth, sectionAccess('tickets','view'), (req,res) => {
    const db = loadDB(); ensureSeedProduct(db);
    res.json(filterByProductScope(req, db.tickets).map(t=>{
        const product = db.products.find(p=>p.id===(t.product_id||'sfm'));
        return {...t, product_name: product ? product.name : (t.product_id||'sfm')};
    }).reverse());
});
app.get('/api/tickets/:id', auth, (req,res) => {
    const t=loadDB().tickets.find(t=>t.id===req.params.id);
    if (!t) return res.status(404).json({error:'Not found'});
    res.json(t);
});
app.patch('/api/tickets/:id', auth, sectionAccess('tickets','manage'), (req,res) => {
    const db=loadDB(); const t=db.tickets.find(t=>t.id===req.params.id);
    if (!t) return res.status(404).json({error:'Not found'});
    if (!inProductScope(req, t.product_id)) return res.status(403).json({error:'هذه التذكرة خارج نطاق صلاحيتك'});
    if (req.body.status!==undefined) t.status=req.body.status;
    if (req.body.reply!==undefined)  t.reply=req.body.reply;
    logAdminActivity(db, req.admin.username, 'reply_ticket', `رد على تذكرة: ${t.id}`);
    saveDB(db); res.json({ok:true});
});
app.patch('/api/tickets/:id/status', auth, sectionAccess('tickets','manage'), (req,res) => {
    const db=loadDB(); const t=db.tickets.find(t=>t.id===req.params.id);
    if (!t) return res.status(404).json({error:'Not found'});
    if (!inProductScope(req, t.product_id)) return res.status(403).json({error:'هذه التذكرة خارج نطاق صلاحيتك'});
    t.status=req.body.status;
    logAdminActivity(db, req.admin.username, 'change_ticket_status', `تذكرة ${t.id} → ${req.body.status}`);
    saveDB(db); res.json({ok:true});
});
app.post('/api/tickets/:id/reply', auth, sectionAccess('tickets','manage'), (req,res) => {
    const db=loadDB(); const t=db.tickets.find(t=>t.id===req.params.id);
    if (!t) return res.status(404).json({error:'Not found'});
    if (!inProductScope(req, t.product_id)) return res.status(403).json({error:'هذه التذكرة خارج نطاق صلاحيتك'});
    if (!t.replies) t.replies=[];
    t.replies.push({body:req.body.reply,from:'admin',at:new Date().toISOString()});
    t.status='pending'; saveDB(db); res.json({ok:true});
});
app.delete('/api/tickets/:id', auth, sectionAccess('tickets','manage'), (req,res) => {
    const db=loadDB();
    const target = db.tickets.find(t=>t.id===req.params.id);
    if (target && !inProductScope(req, target.product_id)) return res.status(403).json({error:'هذه التذكرة خارج نطاق صلاحيتك'});
    db.tickets=db.tickets.filter(t=>t.id!==req.params.id);
    logAdminActivity(db, req.admin.username, 'delete_ticket', `حذف تذكرة: ${req.params.id}`);
    saveDB(db); res.json({ok:true});
});
app.post('/api/tickets/bulk-delete', auth, sectionAccess('tickets','manage'), (req,res) => {
    const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
    if (!ids.length) return res.status(400).json({error:'لا توجد عناصر محددة'});
    const db=loadDB();
    db.tickets=db.tickets.filter(t=>!ids.includes(t.id));
    logAdminActivity(db, req.admin.username, 'bulk_delete_tickets', `حذف ${ids.length} تذكرة`);
    saveDB(db); res.json({ok:true, count: ids.length});
});

// ── Files ──
app.get('/api/files', auth, sectionAccess('files','view'), (req,res) => {
    const limit=parseInt(req.query.limit)||200;
    const status=req.query.status;
    const db = loadDB(); ensureSeedProduct(db);
    let files = filterByProductScope(req, db.files);
    if (status) files = files.filter(f=>f.status===status);
    res.json(files.slice(-limit).reverse().map(f=>{
        const product = db.products.find(p=>p.id===(f.product_id||'sfm'));
        return {...f, product_name: product ? product.name : (f.product_id||'sfm')};
    }));
});

// ── Activity ──
app.get('/api/activity', auth, sectionAccess('activity','view'), (req,res) => {
    const limit=parseInt(req.query.limit)||200;
    const db = loadDB();
    const products = db.products || [];
    const activity = filterByProductScope(req, db.activity, 'product_id').slice(-limit).reverse();
    res.json(activity.map(a => {
        const product = products.find(p => p.id === (a.product_id||'sfm'));
        return {...a, product_name: product ? product.name : (a.product_id||'sfm'), product_icon: product ? product.icon : '📦'};
    }));
});
app.delete('/api/activity/clear', auth, sectionAccess('activity','manage'), (req,res) => {
    const db=loadDB(); db.activity=[]; saveDB(db); res.json({ok:true});
});

// ── نشاط مستخدمي موقع Softora (منفصل عن نشاط برنامج سطح المكتب أعلاه) ──
// موقع Softora يستدعي هذا الرابط فور حدوث فعل مهم (دخول، تسجيل جديد،
// شراء...) بنفس مفتاح العميل المستخدم أصلاً لإصدار التراخيص — لا يحتاج
// أي إعداد إضافي بجهة Softora
app.post('/client/website-activity', clientAuth, (req,res) => {
    const {event_type, email, name, details} = req.body;
    if (!event_type) return res.status(400).json({error:'event_type مطلوب'});
    const db = loadDB();
    if (!db.website_activity) db.website_activity = [];
    db.website_activity.push({
        id: nextId(db.website_activity), event_type,
        email: email || '', name: name || '',
        details: details || '',
        ip: getClientIp(req),
        created_at: new Date().toISOString(),
    });
    if (db.website_activity.length > 5000) db.website_activity = db.website_activity.slice(-5000);
    saveDB(db);
    res.json({ok:true});
});
app.get('/api/website-activity', auth, sectionAccess('website_activity','view'), (req,res) => {
    const limit = parseInt(req.query.limit) || 300;
    res.json((loadDB().website_activity || []).slice(-limit).reverse());
});
app.delete('/api/website-activity/clear', auth, sectionAccess('website_activity','manage'), (req,res) => {
    const db = loadDB(); db.website_activity = []; saveDB(db); res.json({ok:true});
});

// ── Commands ──
app.get('/api/commands', auth, sectionAccess('commands','view'), (req,res) => {
    const db = loadDB(); ensureSeedProduct(db);
    res.json(filterByProductScope(req, db.commands).map(c=>{
        const product = db.products.find(p=>p.id===(c.product_id||'sfm'));
        return {...c, product_name: product ? product.name : (c.product_id||'sfm')};
    }).reverse());
});
app.post('/api/commands', auth, sectionAccess('commands','manage'), (req,res) => {
    const {user_id,command,data,product_id} = req.body;
    if (!user_id||!command) return res.status(400).json({error:'Missing fields'});
    const resolvedProductId = product_id || 'sfm';
    if (!inProductScope(req, resolvedProductId)) return res.status(403).json({error:'هذا المنتج خارج نطاق صلاحيتك'});
    const db=loadDB();
    const cmd={id:nextId(db.commands),user_id,command,data:data||null,product_id:resolvedProductId,status:'pending',created_at:new Date().toISOString()};
    db.commands.push(cmd);
    logAdminActivity(db, req.admin.username, 'send_command', `${command} → ${user_id} (${resolvedProductId})`);
    saveDB(db); res.json({ok:true,id:cmd.id});
});

// ── Notifications ──
app.get('/api/notifications', auth, sectionAccess('notifications','view'), (req,res) => res.json(loadDB().notifications.slice().reverse()));
app.post('/api/notifications', auth, sectionAccess('notifications','manage'), (req,res) => {
    const {user_id,title,message} = req.body;
    if (!message) return res.status(400).json({error:'Missing message'});
    const db=loadDB();
    const n={id:nextId(db.notifications),user_id:user_id||'all',title:title||'إشعار',message,read:0,created_at:new Date().toISOString()};
    db.notifications.push(n);
    logAdminActivity(db, req.admin.username, 'send_notification', `إلى: ${n.user_id} — ${n.title}`);
    saveDB(db); res.json({ok:true,id:n.id});
});
app.patch('/api/notifications/:id/read', auth, sectionAccess('notifications','manage'), (req,res) => {
    const db=loadDB(); const n=db.notifications.find(n=>n.id===parseInt(req.params.id));
    if (n) { n.read=1; saveDB(db); } res.json({ok:true});
});
app.delete('/api/notifications/:id', auth, sectionAccess('notifications','manage'), (req,res) => {
    const db=loadDB();
    db.notifications=db.notifications.filter(n=>n.id!==parseInt(req.params.id));
    saveDB(db); res.json({ok:true});
});
app.post('/api/notifications/bulk-delete', auth, sectionAccess('notifications','manage'), (req,res) => {
    const ids = Array.isArray(req.body.ids) ? req.body.ids.map(Number) : [];
    if (!ids.length) return res.status(400).json({error:'لا توجد عناصر محددة'});
    const db=loadDB();
    db.notifications=db.notifications.filter(n=>!ids.includes(n.id));
    logAdminActivity(db, req.admin.username, 'bulk_delete_notifications', `حذف ${ids.length} إشعار`);
    saveDB(db); res.json({ok:true, count: ids.length});
});

// ── Version ──
// ── إصدارات المنتجات (Updates) — كانت إصداراً عاماً واحداً لكل النظام
// (db.version)، وهذا لا يصح مع تعدد المنتجات: كل منتج له رقم إصدار وملف
// تنزيل مستقل. نحوّلها الآن لكائن مفهرَس بمعرّف المنتج (db.versions)، مع
// ترحيل تلقائي للإصدار القديم كـ'sfm' حتى لا تنكسر البيانات الحالية
function getVersions(db) {
    if (!db.versions) {
        db.versions = {};
        if (db.version) db.versions.sfm = db.version; // ترحيل من البنية القديمة
    }
    return db.versions;
}
app.get('/api/version', auth, sectionAccess('updates','view'), (req,res) => {
    const db = loadDB();
    const productId = req.query.product_id || 'sfm';
    if (!inProductScope(req, productId)) return res.status(403).json({error:'هذا المنتج خارج نطاق صلاحيتك'});
    const versions = getVersions(db);
    res.json(versions[productId] || {version:'', download_url:'', notes:''});
});
app.post('/api/version', auth, sectionAccess('updates','manage'), (req,res) => {
    const db=loadDB();
    const productId = req.body.product_id || 'sfm';
    if (!inProductScope(req, productId)) return res.status(403).json({error:'هذا المنتج خارج نطاق صلاحيتك'});
    const versions = getVersions(db);
    // لو ما حدّد المشرف رابط تحميل يدوي (الحالة الشائعة الآن بعد إضافة رفع
    // الملف المباشر)، نوجّه المستخدم لموقع Softora نفسه، حيث يقدر يسجّل
    // دخوله ويحمّل الملف الأحدث من صفحة اشتراكاته بأمان (مسار تحميل موثّق
    // أصلاً بالتحقق من الاشتراك)، بدل رابط مباشر غير محمي لملف بلا تحقق
    const download_url = (req.body.download_url || '').trim() || SOFTORA_URL;
    versions[productId] = {version:req.body.version,download_url,notes:req.body.notes||'',released_at:new Date().toISOString()};
    logAdminActivity(db, req.admin.username, 'publish_update', `${productId} — الإصدار ${req.body.version}`);
    saveDB(db); res.json({ok:true});
});

// ── خطط الأسعار (Pricing Plans) — ديناميكية بالكامل، تُدار من هنا بدل
// كونها نصوصاً ثابتة مكتوبة داخل كود موقع Softora مباشرة. أي تعديل هنا
// (سعر، خصم، مميزة جديدة...) ينعكس فوراً على الموقع، وعلى مبلغ الدفع
// الفعلي أيضاً — موقع Softora يتحقق من السعر هنا وقت الدفع نفسه، مش بس
// وقت العرض، فمستحيل يصير فرق بين اللي يشوفه العميل واللي يُخصم منه ──
app.get('/api/pricing-plans', auth, sectionAccess('pricing_plans','view'), (req,res) => {
    const db = loadDB();
    ensureSeedPricingPlans(db);
    res.json(filterByProductScope(req, db.pricing_plans, 'product_id').sort((a,b)=>(a.order||0)-(b.order||0)));
});
app.post('/api/pricing-plans', auth, sectionAccess('pricing_plans','manage'), (req,res) => {
    const {product_id, name, name_en, desc, desc_en, price_monthly, price_yearly, discount_percent, max_devices, popular, features} = req.body;
    if (!name || !product_id) return res.status(400).json({error:'اسم الخطة والمنتج مطلوبان'});
    if (!inProductScope(req, product_id)) return res.status(403).json({error:'هذا المنتج خارج نطاق صلاحيتك'});
    const db = loadDB();
    if (!db.pricing_plans) db.pricing_plans = [];
    const id = slugify(name) + '-' + Date.now().toString(36);
    const maxOrder = db.pricing_plans.filter(p=>p.product_id===product_id).reduce((m,p)=>Math.max(m,p.order||0),0);
    const plan = {
        id, product_id, name, name_en: name_en||'', desc: desc||'', desc_en: desc_en||'',
        price_monthly: Math.max(0, Number(price_monthly)||0), price_yearly: Math.max(0, Number(price_yearly)||0),
        // نحصر نسبة الخصم بين 0 و100 دائماً — بدون هذا الحد، قيمة أعلى من
        // 100 تجعل السعر النهائي سالباً (final = price * (1 - discount/100))،
        // وقيمة سالبة تجعل "الخصم" يرفع السعر بدل ما ينزّله، وكلاهما خطأ
        // منطقي خطير يمكن يفلت من أي فحص عين بسيط عند الحفظ
        discount_percent: Math.min(100, Math.max(0, Number(discount_percent)||0)), max_devices: Math.max(1, Number(max_devices)||1),
        popular: !!popular, active: true, order: maxOrder+1,
        features: Array.isArray(features) ? features : [],
        created_at: new Date().toISOString(),
    };
    db.pricing_plans.push(plan);
    logAdminActivity(db, req.admin.username, 'create_pricing_plan', `${plan.name} — ${product_id}`);
    saveDB(db);
    notifySoftoraChanged('pricing');
    res.json({ok:true, plan});
});
app.patch('/api/pricing-plans/:id', auth, sectionAccess('pricing_plans','manage'), (req,res) => {
    const db = loadDB();
    if (!db.pricing_plans) db.pricing_plans = [];
    const p = db.pricing_plans.find(p=>p.id===req.params.id);
    if (!p) return res.status(404).json({error:'الخطة غير موجودة'});
    if (!inProductScope(req, p.product_id)) return res.status(403).json({error:'هذه الخطة خارج نطاق صلاحيتك'});
    const fields = ['name','name_en','desc','desc_en','popular','active','features'];
    fields.forEach(f => { if (req.body[f]!==undefined) p[f]=req.body[f]; });
    // نفس حدود الأمان المطبَّقة عند الإنشاء — نطبّقها هنا أيضاً عند التعديل،
    // وإلا يقدر أي تعديل لاحق يتحايل عليها ويحفظ خصماً >100% أو سعراً سالباً
    if (req.body.price_monthly   !== undefined) p.price_monthly   = Math.max(0, Number(req.body.price_monthly)||0);
    if (req.body.price_yearly    !== undefined) p.price_yearly    = Math.max(0, Number(req.body.price_yearly)||0);
    if (req.body.discount_percent!== undefined) p.discount_percent= Math.min(100, Math.max(0, Number(req.body.discount_percent)||0));
    if (req.body.max_devices     !== undefined) p.max_devices     = Math.max(1, Number(req.body.max_devices)||1);
    if (req.body.order           !== undefined) p.order           = Number(req.body.order)||0;
    p.updated_at = new Date().toISOString();
    logAdminActivity(db, req.admin.username, 'update_pricing_plan', `${p.name} — ${p.product_id}`);
    saveDB(db);
    notifySoftoraChanged('pricing');
    res.json({ok:true, plan:p});
});
app.delete('/api/pricing-plans/:id', auth, sectionAccess('pricing_plans','manage'), (req,res) => {
    const db = loadDB();
    if (!db.pricing_plans) db.pricing_plans = [];
    const p = db.pricing_plans.find(p=>p.id===req.params.id);
    if (!p) return res.status(404).json({error:'الخطة غير موجودة'});
    if (!inProductScope(req, p.product_id)) return res.status(403).json({error:'هذه الخطة خارج نطاق صلاحيتك'});
    db.pricing_plans = db.pricing_plans.filter(x=>x.id!==req.params.id);
    logAdminActivity(db, req.admin.username, 'delete_pricing_plan', `${p.name} — ${p.product_id}`);
    saveDB(db);
    notifySoftoraChanged('pricing');
    res.json({ok:true});
});
// نقطة قراءة عامة للخطط النشطة فقط — يستخدمها موقع Softora لعرض الأسعار
// *وللتحقق من صحة السعر وقت الدفع نفسه* (راجع routes/payment.js بمشروع Softora)
app.get('/client/pricing', clientAuth, (req,res) => {
    const db = loadDB();
    ensureSeedPricingPlans(db);
    const productId = req.query.product_id || 'sfm';
    const plans = db.pricing_plans
        .filter(p => p.product_id === productId && p.active)
        .sort((a,b)=>(a.order||0)-(b.order||0))
        .map(p => {
            // السعر الفعلي بعد الخصم — نحسبه هنا (مصدر الحقيقة الوحيد)، لا
            // نترك موقع Softora يحسبه بنفسه، تفادياً لأي تلاعب أو خطأ حساب بالطرف الآخر
            const discount = p.discount_percent || 0;
            const final_monthly = Math.round(p.price_monthly * (1 - discount/100));
            const final_yearly  = Math.round(p.price_yearly  * (1 - discount/100));
            return {
                id: p.id, name: p.name, name_en: p.name_en, desc: p.desc, desc_en: p.desc_en,
                price_monthly: p.price_monthly, price_yearly: p.price_yearly,
                final_monthly, final_yearly, discount_percent: discount,
                max_devices: p.max_devices, popular: p.popular, features: p.features||[],
            };
        });
    res.json(plans);
});

// ── وضع الصيانة (Site Maintenance) — يتحكم بإغلاق موقع Softora بالكامل عن
// الزوار العاديين، مع إبقاء وصول خاص للمالك عبر رمز تجاوز (bypass token)
// لمعاينة/اختبار الموقع أثناء إغلاقه. الفحص يحصل على كل طلب بموقع Softora
// نفسه (راجع middleware الصيانة بمشروع Softora) — هنا فقط مصدر الحالة ──
app.get('/api/site-maintenance', auth, sectionAccess('site_maintenance','view'), (req,res) => {
    const db = loadDB();
    const m = db.site_maintenance || {enabled:false, message:'', message_en:'', bypass_token:''};
    res.json({...m, bypass_url: m.bypass_token ? `${SOFTORA_URL}/?bypass=${m.bypass_token}` : ''});
});
app.patch('/api/site-maintenance', auth, sectionAccess('site_maintenance','manage'), (req,res) => {
    const db = loadDB();
    if (!db.site_maintenance) db.site_maintenance = {enabled:false, message:'', message_en:'', bypass_token:''};
    const {enabled, message, message_en, regenerate_token} = req.body;
    if (enabled!==undefined) db.site_maintenance.enabled = !!enabled;
    if (message!==undefined) db.site_maintenance.message = message;
    if (message_en!==undefined) db.site_maintenance.message_en = message_en;
    if (regenerate_token || !db.site_maintenance.bypass_token) {
        db.site_maintenance.bypass_token = crypto.randomBytes(16).toString('hex');
    }
    db.site_maintenance.updated_at = new Date().toISOString();
    logAdminActivity(db, req.admin.username, db.site_maintenance.enabled ? 'enable_maintenance' : 'disable_maintenance', 'موقع Softora');
    saveDB(db);
    notifySoftoraChanged('maintenance');
    res.json({ok:true, site_maintenance: {...db.site_maintenance, bypass_url: `${SOFTORA_URL}/?bypass=${db.site_maintenance.bypass_token}`}});
});
app.get('/client/site-maintenance', clientAuth, (req,res) => {
    const db = loadDB();
    const m = db.site_maintenance || {enabled:false, message:'', message_en:'', bypass_token:''};
    res.json({enabled: m.enabled, message: m.message, message_en: m.message_en, bypass_token: m.bypass_token});
});

const LICENSE_STATUSES=['active','suspended','cancelled'];
// يحسب تاريخ الانتهاء بناءً على تاريخ التفعيل الفعلي (مو تاريخ الإنشاء)
function computeExpiryFromActivation(plan, activatedAtISO) {
    if (plan==='lifetime') return null;
    const d = new Date(activatedAtISO);
    if (plan==='trial')        d.setDate(d.getDate()+14);
    else if (plan==='monthly') d.setMonth(d.getMonth()+1);
    else if (plan==='yearly')  d.setDate(d.getDate()+365);
    else return null;
    return d.toISOString().slice(0,10);
}
app.get('/api/licenses', auth, sectionAccess('licenses','view'), (req,res) => {
    const db=loadDB();
    ensureSeedProduct(db);
    let changed=false;
    db.licenses.forEach(l=>{
        if (!l.status) { l.status = l.cancelled ? 'cancelled' : 'active'; changed=true; }
        if (!l.product_id) { l.product_id = 'sfm'; changed=true; }
        // إصلاح ذاتي: ترخيص "مدى الحياة" لا يجب أن يملك تاريخ انتهاء إطلاقاً
        if (l.plan === 'lifetime' && l.expires_at) { l.expires_at = null; changed=true; }
        const expired = l.plan!=='lifetime' && l.expires_at ? new Date(l.expires_at) < new Date() : false;
        if (expired && l.status!=='cancelled') { l.status='cancelled'; l.cancelled=true; l.cancel_reason='expired'; changed=true; }
    });
    if (changed) saveDB(db);
    res.json(filterByProductScope(req, db.licenses).map(l=>{
        const product = db.products.find(p=>p.id===l.product_id);
        return {...l,
            devices:(db.license_devices||[]).filter(d=>d.license_key===l.key),
            isExpired:l.plan!=='lifetime' && l.expires_at ? new Date(l.expires_at)<new Date() : false,
            isCancelled: !!l.cancelled,
            isPending: l.plan!=='lifetime' && !l.activated_at,
            product_name: product ? product.name : l.product_id,
            product_icon: product ? product.icon : '📦',
        };
    }));
});
function createLicenseRecord(db, {email, name, plan='trial', max_devices=1, notes, product_id='sfm'}) {
    ensureSeedProduct(db);
    const product = db.products.find(p=>p.id===product_id);
    if (!product) return {error:'المنتج غير موجود'};
    const now=new Date();
    // الفحص الآن لكل منتج على حدة — المستخدم يقدر يملك ترخيص فعّال لأكثر من برنامج بنفس الوقت
    const existing = db.licenses.find(l => l.email===email && l.product_id===product_id && l.status!=='cancelled' && (!l.expires_at || new Date(l.expires_at) >= now));
    if (existing) return {error:'هذا المستخدم لديه ترخيص فعّال بالفعل لهذا المنتج ('+existing.key+') — يجب إلغاؤه أولاً قبل إنشاء ترخيص جديد'};
    const prefix = (product.slug||product_id).toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,4) || 'LIC';
    const chars='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const seg=()=>Array.from({length:4},()=>chars[Math.floor(Math.random()*chars.length)]).join('');
    const key=prefix+'-'+seg()+'-'+seg()+'-'+seg()+'-'+seg();
    // ملاحظة: تاريخ الانتهاء لا يُحسب الآن — يُحسب لحظة أول تفعيل فعلي من
    // البرنامج (activated_at)، حتى تكون مدة الترخيص كاملة فعلاً للمستخدم
    // بغض النظر عن الوقت اللي مضى بين الإنشاء والتفعيل.
    const record = {key,plan,email,name:name||'',max_devices,product_id,expires_at:null,activated_at:null,notes:notes||'',cancelled:false,status:'active',created_at:new Date().toISOString()};
    db.licenses.push(record);
    return {ok:true,key,plan};
}
app.post('/api/licenses', auth, sectionAccess('licenses','manage'), (req,res) => {
    const {email,name,plan='trial',max_devices=1,notes,product_id='sfm'} = req.body;
    if (!email) return res.status(400).json({error:'البريد مطلوب'});
    const db=loadDB();
    const result = createLicenseRecord(db, {email,name,plan,max_devices,notes,product_id});
    if (result.error) return res.status(400).json({error:result.error});
    logAdminActivity(db, req.admin.username, 'create_license', `${result.key} — ${email} (${plan})`);
    saveDB(db);
    const plans={trial:'تجريبي',monthly:'شهري',yearly:'سنوي',lifetime:'مدى الحياة'};
    res.json({ok:true,key:result.key,plan,planLabel:plans[plan]||plan});
});
// ── إصدار ترخيص آلي من خدمة خارجية موثوقة (مثل موقع Softora بعد نجاح الدفع) ──
// يستخدم نفس مفتاح x-api-key المستخدم من البرنامج، وليس توكن المدير
app.post('/client/licenses/issue', clientAuth, (req,res) => {
    const {email,name,plan='monthly',max_devices=1,notes,order_id,product_id='sfm'} = req.body;
    if (!email) return res.status(400).json({error:'البريد مطلوب'});
    if (!['trial','monthly','yearly','lifetime'].includes(plan)) return res.status(400).json({error:'خطة غير صالحة'});
    const db=loadDB();
    const fullNotes = (notes||'') + (order_id ? ` [order:${order_id}]` : '');
    const result = createLicenseRecord(db, {email,name,plan,max_devices,notes:fullNotes,product_id});
    if (result.error) return res.status(400).json({error:result.error});
    logAdminActivity(db, 'softora-payment', 'auto_issue_license', `${result.key} — ${email} (${plan}) — طلب: ${order_id||'—'}`);
    saveDB(db);
    res.json({ok:true,key:result.key,plan});
});
// ── تجديد ترخيص موجود (بدل رفضه كتكرار) — يمدد تاريخ الانتهاء، أو يعيد
// تفعيل ترخيص منتهي/ملغى بدل إنشاء واحد جديد منفصل ──
app.post('/client/licenses/renew', clientAuth, (req,res) => {
    const {email, name, plan, max_devices, order_id, product_id='sfm'} = req.body;
    if (!email || !plan) return res.status(400).json({error:'بيانات ناقصة'});
    if (!['trial','monthly','yearly','lifetime'].includes(plan)) return res.status(400).json({error:'خطة غير صالحة'});
    const db = loadDB();
    ensureSeedProduct(db);
    const product = db.products.find(p=>p.id===product_id);
    if (!product) return res.status(400).json({error:'المنتج غير موجود'});

    const licenses = db.licenses.filter(l => l.email===email && l.product_id===product_id);
    licenses.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
    const lic = licenses[0];

    if (!lic) {
        // ما فيه ترخيص سابق أصلاً لهذا العميل بهذا المنتج — نعامله كإصدار جديد عادي
        const result = createLicenseRecord(db, {email, name, plan, max_devices:max_devices||1, notes:(order_id?`[order:${order_id}]`:''), product_id});
        if (result.error) return res.status(400).json({error:result.error});
        logAdminActivity(db, 'softora-payment', 'auto_renew_license_new', `${result.key} — ${email} (${plan})`);
        saveDB(db);
        return res.json({ok:true, key:result.key, plan});
    }

    // نمدد من تاريخ الانتهاء الحالي لو لسا بالمستقبل (تجديد مبكر ما يضيّع أيام
    // مدفوعة سابقاً)، وإلا نبدأ الحساب من الآن
    const base = (lic.expires_at && new Date(lic.expires_at) > new Date()) ? lic.expires_at : new Date().toISOString();
    lic.expires_at = plan==='lifetime' ? null : computeExpiryFromActivation(plan, base);
    if (!lic.activated_at) lic.activated_at = new Date().toISOString();
    lic.plan = plan;
    lic.status = 'active';
    lic.cancelled = false;
    lic.cancel_reason = null;
    if (max_devices) lic.max_devices = max_devices;
    lic.notes = (lic.notes||'') + (order_id ? ` [renewed order:${order_id}]` : '');
    logAdminActivity(db, 'softora-payment', 'auto_renew_license', `${lic.key} — ${email} (${plan}) — طلب: ${order_id||'—'}`);
    saveDB(db);
    res.json({ok:true, key:lic.key, plan, expires_at:lic.expires_at});
});
// ── إلغاء ترخيص من طرف العميل نفسه (بعد ما يلغي اشتراكه بموقع Softora) ──
app.post('/client/licenses/cancel', clientAuth, (req,res) => {
    const {email, product_id='sfm'} = req.body;
    if (!email) return res.status(400).json({error:'البريد مطلوب'});
    const db = loadDB();
    const lic = db.licenses.find(l => l.email===email && l.product_id===product_id && l.status!=='cancelled');
    if (!lic) return res.status(404).json({error:'لا يوجد ترخيص فعّال لإلغائه'});
    lic.status = 'cancelled';
    lic.cancelled = true;
    lic.cancel_reason = 'customer_cancelled';
    logAdminActivity(db, 'softora-customer', 'cancel_license', `${lic.key} — ${email}`);
    saveDB(db);
    res.json({ok:true});
});
// ── تسجيل عمليات الدفع القادمة من موقع Softora (للعرض والتقارير بلوحة التحكم) ──
app.post('/client/payments/record', clientAuth, (req,res) => {
    const {order_id,email,name,product_id='sfm',plan_id,billing,amount,currency='SAR',payment_method,card_last4,moyasar_payment_id,license_key,paid_at} = req.body;
    if (!email || !order_id) return res.status(400).json({error:'بيانات ناقصة'});
    const db=loadDB();
    if (!db.payments) db.payments=[];
    // idempotent: نفس الطلب ما يتكرر لو أُرسل أكثر من مرة (مثلاً محاولة ويب هوك متكررة)
    const existing = db.payments.find(p=>p.order_id===order_id);
    const record = {
        order_id, email, name: name||'', product_id, plan_id, billing,
        amount: amount||0, currency, payment_method: payment_method||'creditcard', card_last4: card_last4||null,
        moyasar_payment_id: moyasar_payment_id||null, license_key: license_key||null,
        status: 'paid', paid_at: paid_at || new Date().toISOString(),
        recorded_at: new Date().toISOString(),
    };
    if (existing) Object.assign(existing, record);
    else db.payments.push(record);
    saveDB(db);
    res.json({ok:true});
});
// ── عرض المدفوعات بلوحة التحكم ──
app.get('/api/payments', auth, sectionAccess('payments','view'), (req,res) => {
    const db=loadDB();
    ensureSeedProduct(db);
    res.json(filterByProductScope(req, db.payments||[]).map(p=>{
        const product = db.products.find(pr=>pr.id===p.product_id);
        return {...p, product_name: product ? product.name : p.product_id};
    }).sort((a,b)=> new Date(b.paid_at) - new Date(a.paid_at)));
});
app.delete('/api/payments/:order_id', auth, sectionAccess('payments','manage'), (req,res) => {
    const db = loadDB();
    const target = (db.payments||[]).find(p => p.order_id === req.params.order_id);
    if (!target) return res.status(404).json({error:'غير موجود'});
    if (!inProductScope(req, target.product_id)) return res.status(403).json({error:'هذه الدفعة خارج نطاق صلاحيتك'});
    db.payments = db.payments.filter(p => p.order_id !== req.params.order_id);
    logAdminActivity(db, req.admin.username, 'delete_payment', `${req.params.order_id} — ${target.email}`);
    saveDB(db);
    res.json({ok:true});
});
app.patch('/api/licenses/:key/status', auth, sectionAccess('licenses','manage'), (req,res) => {
    const db=loadDB(); const l=db.licenses.find(l=>l.key===req.params.key);
    if (!l) return res.status(404).json({error:'Not found'});
    if (!inProductScope(req, l.product_id)) return res.status(403).json({error:'هذا الترخيص خارج نطاق صلاحيتك'});
    const status=req.body.status;
    if (!LICENSE_STATUSES.includes(status)) return res.status(400).json({error:'حالة غير صالحة'});
    l.status=status; l.cancelled=(status!=='active'); l.cancel_reason=status==='cancelled'?'manual':(status==='suspended'?'suspended':null);
    logAdminActivity(db, req.admin.username, 'change_license_status', `${l.key} → ${status}`);
    saveDB(db); res.json({ok:true,status:l.status});
});
app.patch('/api/licenses/:key', auth, sectionAccess('licenses','manage'), (req,res) => {
    const db=loadDB(); const l=db.licenses.find(l=>l.key===req.params.key);
    if (!l) return res.status(404).json({error:'Not found'});
    if (!inProductScope(req, l.product_id)) return res.status(403).json({error:'هذا الترخيص خارج نطاق صلاحيتك'});
    const {email,name,plan,max_devices,expires_at,notes,product_id} = req.body;
    if (product_id!==undefined && !inProductScope(req, product_id)) return res.status(403).json({error:'لا يمكنك نقل الترخيص لمنتج خارج نطاق صلاحيتك'});
    if (product_id!==undefined) {
        ensureSeedProduct(db);
        if (!db.products.find(p=>p.id===product_id)) return res.status(400).json({error:'المنتج غير موجود'});
        l.product_id = product_id;
    }
    if (email!==undefined) {
        if (!email) return res.status(400).json({error:'البريد مطلوب'});
        const dup = db.licenses.find(x=>x.key!==l.key && x.email===email && x.product_id===l.product_id && x.status!=='cancelled' && (!x.expires_at || new Date(x.expires_at)>=new Date()));
        if (dup) return res.status(400).json({error:'هذا البريد لديه ترخيص فعّال آخر لنفس المنتج بالفعل ('+dup.key+')'});
        l.email=email;
    }
    if (name!==undefined)         l.name=name;
    const planChanged = plan!==undefined && plan!==l.plan;
    if (plan!==undefined)         l.plan=plan;
    if (max_devices!==undefined) {
        const md=parseInt(max_devices);
        if (!Number.isInteger(md) || md<1) return res.status(400).json({error:'عدد الأجهزة يجب أن يكون رقماً صحيحاً 1 أو أكثر'});
        l.max_devices=md;
    }
    if (l.plan === 'lifetime') {
        l.expires_at = null;
    } else if (planChanged && l.activated_at) {
        // الترخيص مُفعَّل فعلاً — أعد حساب تاريخ الانتهاء بناءً على تاريخ التفعيل الأصلي والخطة الجديدة
        l.expires_at = computeExpiryFromActivation(l.plan, l.activated_at);
    } else if (planChanged && !l.activated_at) {
        // لم يُفعَّل بعد — يبقى تاريخ الانتهاء معلّقاً حتى أول تفعيل فعلي
        l.expires_at = null;
    } else if (expires_at!==undefined) {
        // تعديل يدوي صريح لتاريخ الانتهاء بدون تغيير الخطة
        l.expires_at = expires_at || null;
    }
    if (notes!==undefined)        l.notes=notes;
    logAdminActivity(db, req.admin.username, 'edit_license', `تعديل ترخيص: ${l.key}`);
    saveDB(db); res.json({ok:true});
});
app.patch('/api/licenses/:key/cancel', auth, sectionAccess('licenses','manage'), (req,res) => {
    const db=loadDB(); const l=db.licenses.find(l=>l.key===req.params.key);
    if (!l) return res.status(404).json({error:'Not found'});
    if (!inProductScope(req, l.product_id)) return res.status(403).json({error:'هذا الترخيص خارج نطاق صلاحيتك'});
    l.cancelled=true; l.status='cancelled'; l.cancel_reason='manual';
    logAdminActivity(db, req.admin.username, 'cancel_license', l.key);
    saveDB(db); res.json({ok:true});
});
app.delete('/api/licenses/:key', auth, sectionAccess('licenses','manage'), (req,res) => {
    const db=loadDB();
    const target = db.licenses.find(l=>l.key===req.params.key);
    if (target && !inProductScope(req, target.product_id)) return res.status(403).json({error:'هذا الترخيص خارج نطاق صلاحيتك'});
    db.licenses=db.licenses.filter(l=>l.key!==req.params.key);
    db.license_devices=(db.license_devices||[]).filter(d=>d.license_key!==req.params.key);
    logAdminActivity(db, req.admin.username, 'delete_license', req.params.key);
    saveDB(db); res.json({ok:true});
});

// ═══════════════ CLIENT ROUTES ═══════════════

app.post('/client/user', clientAuth, (req,res) => {
    const {id,username,name,email,files_count,disks_count,storage_used,machine_id,role,password_hash}=req.body;
    if (!id||!username) return res.status(400).json({error:'Missing fields'});
    const ip=req.headers['x-forwarded-for']?.split(',')[0]||req.socket.remoteAddress||'';
    const db=loadDB();
    const idx=db.users.findIndex(u=>u.id===id||u.username===username);
    const existing = idx!==-1 ? db.users[idx] : null;
    const isAdminUser = username==='admin';
    const user={
        id,username,name:name||'',email:email||'',
        role: isAdminUser ? 'admin' : (role||existing?.role||'user'),
        ip_address:ip,machine_id:machine_id||'',
        files_count:files_count||0,disks_count:disks_count||0,storage_used:storage_used||0,
        last_active:new Date().toISOString(),
        status: isAdminUser ? 'active' : (existing?.status || 'active'),
        password_hash: password_hash!==undefined ? password_hash : (existing?.password_hash||'')
    };
    if (idx!==-1) { db.users[idx]={...db.users[idx],...user}; }
    else { db.users.push({...user,created_at:new Date().toISOString()}); }
    saveDB(db); res.json({ok:true});
});

app.get('/client/user-status/:id', clientAuth, (req,res) => {
    const db=loadDB();
    const u=db.users.find(u=>u.id===req.params.id||u.username===req.params.id);
    res.json({status:u?.status||'active'});
});

app.post('/client/files', clientAuth, (req,res) => {
    const {user_id,files,product_id}=req.body;
    if (!user_id||!Array.isArray(files)) return res.status(400).json({error:'Missing fields'});
    // نحدد المنتج قبل أي شي — هذا مهم جداً هنا تحديداً: كل مزامنة تستبدل
    // *كل* ملفات هذا المستخدم دفعة واحدة (full resync). لو ما حددنا المنتج
    // بالفلترة، مزامنة برنامج واحد كانت تمسح ملفات مسجَّلة من برنامج آخر
    // لنفس المستخدم بالغلط
    const resolvedProductId = product_id || 'sfm';
    const db=loadDB();
    db.files=db.files.filter(f=>!(f.user_id===user_id && (f.product_id||'sfm')===resolvedProductId));
    files.slice(0,500).forEach(f=>{
        const size = f.size_bytes ?? f.sizeBytes ?? (typeof f.size==='number' ? f.size : 0);
        const created_at = f.created_at || f.date || f.createdAt || new Date().toISOString();
        db.files.push({...f, size, created_at, user_id, product_id:resolvedProductId, synced_at:new Date().toISOString()});
    });
    saveDB(db); res.json({ok:true});
});

app.post('/client/ticket', clientAuth, (req,res) => {
    const {id,user_id,type,title,body,product_id}=req.body;
    if (!id||!title||!body) return res.status(400).json({error:'Missing fields'});
    const db=loadDB();
    const existing=db.tickets.find(t=>t.id===id);
    if (!existing) {
        db.tickets.push({id,user_id:user_id||'unknown',type:type||'أخرى',title,body,product_id:product_id||'sfm',status:'open',replies:[],created_at:new Date().toISOString()});
    } else {
        existing.user_id=user_id||existing.user_id;
    }
    saveDB(db); res.json({ok:true});
});

app.get('/client/ticket-replies/:id', clientAuth, (req,res) => {
    const db=loadDB();
    const t=db.tickets.find(t=>t.id===req.params.id);
    res.json(t?.replies||[]);
});

// حالة التذكرة الكاملة (الحالة + الرد) — يستخدمها البرنامج لمزامنة أي تغيير من لوحة التحكم
app.get('/client/tickets/:id', clientAuth, (req,res) => {
    const db=loadDB();
    const t=db.tickets.find(t=>t.id===req.params.id);
    if (!t) return res.status(404).json({error:'Not found'});
    res.json({id:t.id, status:t.status, reply:t.reply||null});
});

app.patch('/client/tickets/:id/close', clientAuth, (req,res) => {
    const db=loadDB();
    const t=db.tickets.find(t=>t.id===req.params.id);
    if (t) { t.status='closed'; saveDB(db); }
    res.json({ok:true});
});

app.post('/client/activity', clientAuth, (req,res) => {
    const {user_id,type,msg,file,product_id}=req.body;
    const db=loadDB();
    // نسمح لكل تطبيق عميل يبلّغ بنشاطه إنه يحدد منتجه بنفسه — مهم إذا صار
    // عندنا أكثر من برنامج سطح مكتب مستقبلاً، كل واحد له معرّف مختلف بلوحة
    // المنتجات. الافتراضي 'sfm' للتوافق مع نسخة العميل الحالية التي لا
    // ترسل هذا الحقل بعد
    db.activity.push({id:nextId(db.activity),user_id,type,msg,file,product_id:product_id||'sfm',created_at:new Date().toISOString()});
    if (db.activity.length>2000) db.activity=db.activity.slice(-2000);
    saveDB(db); res.json({ok:true});
});

app.get('/client/commands/:user_id', clientAuth, (req,res) => {
    const db=loadDB();
    // نفلتر حسب المنتج أيضاً، مو فقط المستخدم — لو نفس المستخدم مثبّت عنده
    // أكثر من برنامج مرتبط بنفس اللوحة، كل برنامج يستلم فقط الأوامر
    // الموجَّهة له تحديداً. الافتراضي 'sfm' للتوافق مع نسخ العميل التي لا
    // ترسل هذا الحقل بعد
    const productId = req.query.product_id || 'sfm';
    res.json(db.commands.filter(c=>c.user_id===req.params.user_id && (c.product_id||'sfm')===productId && c.status==='pending'));
});

app.patch('/client/commands/:id', clientAuth, (req,res) => {
    const db=loadDB();
    const c=db.commands.find(c=>c.id===parseInt(req.params.id));
    if (c) { c.status='done'; c.result=req.body.result!==undefined?req.body.result:(c.result||''); saveDB(db); }
    res.json({ok:true});
});

app.get('/client/notifications/:user_id', clientAuth, (req,res) => {
    const db=loadDB();
    const uid=req.params.user_id;
    res.json(db.notifications.filter(n=>(!n.read)&&(n.user_id===uid||n.user_id==='all')));
});

app.post('/client/notifications/:id/read', clientAuth, (req,res) => {
    const db=loadDB();
    const n=db.notifications.find(n=>n.id===parseInt(req.params.id));
    if (n) { n.read=1; saveDB(db); }
    res.json({ok:true});
});

app.get('/client/version', clientAuth, (req,res) => {
    const db = loadDB();
    const productId = req.query.product_id || 'sfm';
    const versions = getVersions(db);
    res.json(versions[productId] || {version:'1.0.0', download_url:'', notes:''});
});

app.post('/client/license/verify', clientAuth, (req,res) => {
    const {key,machine_id,hostname,platform}=req.body;
    if (!key||!machine_id) return res.status(400).json({valid:false,error:'بيانات ناقصة'});
    const db=loadDB();
    const lic=db.licenses.find(l=>l.key===key);
    if (!lic) return res.json({valid:false,error:'مفتاح الترخيص غير صالح'});
    if (lic.status==='suspended') return res.json({valid:false,error:'الترخيص موقوف مؤقتاً',suspended:true});
    if (lic.cancelled) return res.json({valid:false,error:'تم إلغاء الترخيص',cancelled:true});
    // أول تفعيل فعلي — نحسب تاريخ الانتهاء من الآن، مو من تاريخ إنشاء الترخيص بلوحة التحكم
    let changed=false;
    if (!lic.activated_at && lic.plan!=='lifetime') {
        lic.activated_at = new Date().toISOString();
        lic.expires_at = computeExpiryFromActivation(lic.plan, lic.activated_at);
        changed=true;
    }
    if (lic.plan!=='lifetime' && lic.expires_at && new Date(lic.expires_at)<new Date()) { if(changed) saveDB(db); return res.json({valid:false,error:'انتهت صلاحية الترخيص',expired:true}); }
    const devices=(db.license_devices||[]).filter(d=>d.license_key===key);
    const existing=devices.find(d=>d.machine_id===machine_id);
    if (!existing&&devices.length>=lic.max_devices) { if(changed) saveDB(db); return res.json({valid:false,error:'تجاوز الحد المسموح ('+lic.max_devices+' جهاز)'}); }
    if (!db.license_devices) db.license_devices=[];
    if (existing) { existing.last_seen=new Date().toISOString(); }
    else { db.license_devices.push({license_key:key,machine_id,hostname:hostname||'',platform:platform||'',activated_at:new Date().toISOString(),last_seen:new Date().toISOString()}); }
    saveDB(db);
    const plans={trial:'تجريبي',monthly:'شهري',yearly:'سنوي',lifetime:'مدى الحياة'};
    res.json({valid:true,plan:lic.plan,planLabel:plans[lic.plan]||lic.plan,email:lic.email,name:lic.name,expires_at:lic.plan==='lifetime'?null:lic.expires_at});
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
// ── بدء التشغيل: نتصل بـ MongoDB أولاً، ولا نبدأ الاستماع للطلبات إلا
//    بعد نجاح الاتصال — هذا يمنع تقديم صفحات بدون بيانات حقيقية، ويجعل
//    فشل الاتصال يظهر بوضوح في سجلات Render بدل خادم "يعمل" لكنه فارغ ──
dbModule.connect()
    .then(() => {
        app.listen(PORT, () => console.log('SFM Admin running on port '+PORT));
    })
    .catch(err => {
        console.error('❌ فشل الاتصال بقاعدة البيانات — الخادم لن يبدأ:', err.message);
        process.exit(1);
    });
