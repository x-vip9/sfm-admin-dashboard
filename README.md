# SFM Admin Dashboard

## الرفع على Railway

1. اذهب إلى [railway.app](https://railway.app) وسجّل دخولاً
2. اضغط **New Project** → **Deploy from GitHub**
3. ارفع هذا المجلد كـ GitHub repo
4. أضف هذه المتغيرات في **Variables**:
   ```
   JWT_SECRET=اكتب_هنا_كلمة_سر_عشوائية_طويلة
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=كلمة_مرور_قوية
   CLIENT_API_KEY=sfm-client-key-2024
   ```
5. Railway سيعطيك رابطاً مثل: `https://sfm-admin.up.railway.app`

## ربط التطبيق بلوحة التحكم

في إعدادات التطبيق أضف:
- **API URL**: رابط Railway
- **API Key**: نفس CLIENT_API_KEY

## بيانات الدخول الافتراضية
- المستخدم: `admin`
- كلمة المرور: كما حددتها في Variables

## الصفحات
- **لوحة التحكم**: إحصائيات عامة
- **التذاكر**: عرض والرد على تذاكر الدعم
- **المستخدمون**: قائمة المستخدمين المسجلين
- **سجل النشاط**: نشاطات جميع المستخدمين
- **الإعدادات**: مفتاح API ورابط السيرفر
