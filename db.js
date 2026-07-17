'use strict';
// ═══════════════════════════════════════════════════════════════════
// طبقة تخزين دائمة عبر MongoDB Atlas — تحل محل data.json على القرص
// ═══════════════════════════════════════════════════════════════════
// المشكلة السابقة: Render (الخطة المجانية) يستخدم قرصاً "مؤقتاً"
// (ephemeral) — أي ملف يُكتب أثناء تشغيل الخادم (data.json، النسخ
// الاحتياطية...) يُمسح بالكامل عند كل إعادة نشر (redeploy) أو إعادة
// تشغيل للحاوية، فترجع البيانات فارغة رغم أنها كانت موجودة قبل قليل.
//
// الحل: تخزين كل البيانات في MongoDB Atlas (قاعدة بيانات سحابية دائمة
// مجانية، لا تتأثر بإعادة النشر إطلاقاً).
//
// طريقة العمل — نسخة داخل الذاكرة (in-memory cache) متزامنة مع Mongo:
// كل الكود بباقي server.js يبقى بدون أي تعديل تقريباً (loadDB() و
// saveDB() لهما نفس التوقيع السابق تماماً، وتُستخدمان بنفس الطريقة
// المتزامنة القديمة). عند بدء التشغيل، نجلب البيانات من MongoDB مرة
// واحدة إلى الذاكرة (cache). loadDB() ترجّع نفس هذا الكائن مباشرة.
// saveDB() تحدّث الذاكرة فوراً ثم تكتب النسخة الجديدة في MongoDB في
// الخلفية (الكتابات مُسلسلة عبر writeChain حتى لا يتقاطع ترتيبها).
// ═══════════════════════════════════════════════════════════════════

const { MongoClient, ObjectId, GridFSBucket } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI || '';
const DB_NAME     = process.env.MONGODB_DB  || 'sfm_admin';
const STATE_ID    = 'main';

const DEFAULT_STATE = {
    users: [], tickets: [], files: [], activity: [], commands: [],
    notifications: [], licenses: [], license_devices: [], admins: [],
    admin_activity: [], login_attempts: {}, products: [], payments: [],
    website_activity: [], pricing_plans: [],
    site_maintenance: { enabled: false, message: '', message_en: '', bypass_token: '' },
    version: { version: '1.0.0', download_url: '', notes: '' },
};

let client       = null;
let stateCol     = null;
let backupsCol   = null;
let filesBucket  = null;              // GridFS — تخزين دائم لملفات التثبيت وشعارات الشركاء
let cache        = null;              // نسخة الذاكرة المتزامنة مع Mongo
let writeChain   = Promise.resolve(); // يسلسل الكتابات حتى لا تتضارب
let lastAutoBackup = 0;

async function connect() {
    if (!MONGODB_URI) {
        throw new Error('متغيّر البيئة MONGODB_URI غير مضبوط — لا يمكن للخادم العمل بدون قاعدة بيانات دائمة. راجع ملف .env.example');
    }
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    const database = client.db(DB_NAME);
    stateCol   = database.collection('app_state');
    backupsCol = database.collection('backups');
    // GridFS بدل تخزين الملفات على قرص Render المؤقت — الملفات (شعارات
    // شركاء، ملفات تثبيت برامج) كانت تختفي بكل إعادة نشر بالضبط زي مشكلة
    // data.json القديمة، لأن القرص المحلي "مؤقت" ولا يُعاد استخدامه بين
    // عمليات النشر. GridFS يخزّن الملف داخل MongoDB نفسها فيبقى دائماً.
    filesBucket = new GridFSBucket(database, { bucketName: 'files' });

    const doc = await stateCol.findOne({ _id: STATE_ID });
    if (doc) {
        delete doc._id;
        // ندمج مع القيم الافتراضية حتى لا تنهار الشاشات لو أُضيف حقل
        // جديد للنظام بعد أن كانت قاعدة البيانات قد أُنشئت سابقاً بدونه
        cache = Object.assign({}, DEFAULT_STATE, doc);
    } else {
        cache = JSON.parse(JSON.stringify(DEFAULT_STATE));
        await stateCol.insertOne({ _id: STATE_ID, ...cache });
    }
    console.log('✅ متصل بقاعدة بيانات MongoDB Atlas — البيانات دائمة الآن ولن تُفقد عند إعادة النشر');
}

function loadDB() {
    return cache;
}

function persist(data) {
    writeChain = writeChain
        .then(() => stateCol.replaceOne({ _id: STATE_ID }, { _id: STATE_ID, ...data }, { upsert: true }))
        .catch(err => console.error('❌ فشل حفظ البيانات على MongoDB:', err.message));
    return writeChain;
}

function saveDB(data) {
    cache = data;
    persist(data);
    maybeAutoBackup();
}

// ── نسخ احتياطي تلقائي (مرة كل ساعة كحد أقصى)، ومُدار يدوياً من صفحة
//    "النسخ الاحتياطي" بلوحة التحكم — كلها الآن تُخزَّن داخل Mongo
//    نفسها (مجموعة backups منفصلة)، فتبقى دائمة هي الأخرى ──
function maybeAutoBackup() {
    const now = Date.now();
    if (now - lastAutoBackup < 60 * 60 * 1000) return;
    lastAutoBackup = now;
    createBackupRecord('backup').catch(err => console.error('❌ فشل النسخ الاحتياطي التلقائي:', err.message));
}

async function trimBackups(max = 20) {
    const docs = await backupsCol.find({}, { projection: { _id: 1 } }).sort({ created_at: 1 }).toArray();
    if (docs.length > max) {
        const toDelete = docs.slice(0, docs.length - max).map(d => d._id);
        await backupsCol.deleteMany({ _id: { $in: toDelete } });
    }
}

async function createBackupRecord(prefix) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const name = `${prefix}-${stamp}.json`;
    const json = JSON.stringify(cache);
    await backupsCol.insertOne({
        name,
        created_at: new Date().toISOString(),
        size: Buffer.byteLength(json),
        data: cache,
    });
    await trimBackups();
    return name;
}

async function listBackups() {
    const docs = await backupsCol
        .find({}, { projection: { data: 0 } })
        .sort({ created_at: -1 })
        .toArray();
    return docs.map(d => ({ name: d.name, size: d.size || 0, created_at: d.created_at }));
}

async function getBackupByName(name) {
    return backupsCol.findOne({ name });
}

async function deleteBackupByName(name) {
    const r = await backupsCol.deleteOne({ name });
    return r.deletedCount > 0;
}

async function restoreFromBackup(name) {
    const doc = await backupsCol.findOne({ name });
    if (!doc) return false;
    // نأخذ لقطة من الوضع الحالي قبل الاستبدال احتياطاً، بنفس منطق النسخة القديمة
    await createBackupRecord('pre-restore');
    cache = Object.assign({}, DEFAULT_STATE, doc.data);
    await persist(cache);
    return true;
}

// ── GridFS: تخزين دائم للملفات (ملفات تثبيت، شعارات) ──
// نرفع الملف من بفر بالذاكرة (multer memoryStorage) مباشرة، ونرجّع معرّف
// GridFS كنص — هذا المعرّف هو ما نخزّنه بمكان اسم الملف القديم بقاعدة البيانات
function uploadFile(buffer, filename, contentType) {
    return new Promise((resolve, reject) => {
        const uploadStream = filesBucket.openUploadStream(filename, { contentType });
        uploadStream.on('error', reject);
        uploadStream.on('finish', () => resolve(uploadStream.id.toString()));
        uploadStream.end(buffer);
    });
}
// يبث الملف مباشرة للاستجابة (res) بدون تحميله بالكامل بالذاكرة أولاً —
// مهم لملفات كبيرة (حتى 500 ميغابايت)
function streamFileTo(fileId, res) {
    return new Promise((resolve, reject) => {
        let id;
        try { id = new ObjectId(fileId); } catch (e) { return reject(new Error('معرّف ملف غير صالح')); }
        const downloadStream = filesBucket.openDownloadStream(id);
        downloadStream.on('error', reject);
        downloadStream.on('end', resolve);
        downloadStream.pipe(res);
    });
}
async function deleteFile(fileId) {
    if (!fileId) return;
    try { await filesBucket.delete(new ObjectId(fileId)); } catch (e) { /* ملف غير موجود أصلاً — تجاهل */ }
}
async function getFileInfo(fileId) {
    try {
        const docs = await filesBucket.find({ _id: new ObjectId(fileId) }).toArray();
        return docs[0] || null;
    } catch (e) { return null; }
}

module.exports = {
    connect,
    loadDB,
    saveDB,
    listBackups,
    createBackupRecord,
    getBackupByName,
    deleteBackupByName,
    restoreFromBackup,
    uploadFile,
    streamFileTo,
    deleteFile,
    getFileInfo,
};
