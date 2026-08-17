# DLP Protector Client

אפליקציית Web (Node.js + Express, Frontend ללא build step) לבדיקת קבצים מול Forcepoint DLP
Protector דרך ה-Inspection REST API (v4.0). ה-Frontend מעלה קובץ ל-Backend, וה-Backend בלבד
מדבר עם ה-Protector — ה-Browser אינו נחשף לכתובת/פורט/טוקן של ה-Protector.

> למפתחים: [DEVELOPER.md](DEVELOPER.md) מכיל מדריך טכני מפורט — גם על ה-Web API של
> האפליקציה וגם על הפורמט המדויק של הבקשה ל-Protector עצמו (כולל כמה "gotchas" לא
> מתועדים שגילינו תוך כדי האינטגרציה).

## התקנה

```bash
npm install
```

## הגדרת חיבור (.env)

העתיקו את `.env.example` לקובץ `.env` ומלאו את הפרטים:

```bash
cp .env.example .env
```

| משתנה | תיאור |
|---|---|
| `PROTECTOR_HOST` | כתובת/hostname של ה-Protector |
| `PROTECTOR_PROTOCOL` | `http` או `https` |
| `PROTECTOR_PORT` | פורט (ברירת מחדל: 8080 ל-http, 8443 ל-https) |
| `PROTECTOR_TOKEN` | Bearer token אופציונלי — אם ריק, ה-header לא נשלח כלל |
| `PROTECTOR_CA_CERT_PATH` | נתיב לקובץ CA certificate (PEM), לשימוש עם HTTPS ותעודת self-signed |
| `PROTECTOR_TLS_REJECT_UNAUTHORIZED` | `true`/`false` — האם לוודא את תעודת ה-TLS (false = מקביל ל-`curl -k`) |
| `MAX_FILE_SIZE_MB` | גודל קובץ מקסימלי (ברירת מחדל: 30) |
| `REQUEST_TIMEOUT_MS` | timeout לבקשה מול ה-Protector (ברירת מחדל: 30000) |
| `DESTINATION_HTTP_URL` | נשלח כ-`destinations[0].http_request_url` — נדרש ע"י חלק מהגדרות ה-Protector לצורך resolution של מדיניות/קטגוריית URL |
| `DESTINATION_HTTP_HOSTNAME` | נשלח כ-`destinations[0].http_request_url_hostname` (ה-hostname מתוך ה-URL הנ"ל) |
| `PORT` | הפורט שהשרת המקומי (הזה) מאזין עליו |
| `LOG_FILE_PATH` | נתיב לקובץ הלוג (JSON lines) |

## מסך הגדרות (Settings)

לחיצה על כפתור ה-⚙️ בפינה השמאלית העליונה של ה-UI פותחת מסך הגדרות שבו ניתן לשנות בזמן ריצה
(ללא הפעלה מחדש של השרת) את הפרמטרים הבאים בלבד — כאלה שלא עלולים לשבור את החיבור ל-Protector:

- `MAX_FILE_SIZE_MB`, `REQUEST_TIMEOUT_MS`
- **Source** (נשלח כ-`source` object ב-Inspection Request, ומשמש את ה-Protector להתאמת תנאי
  ה-Source של המדיניות — לפי network/IP או שם מחשב):
  `source.host_ips` (ריק = זיהוי אוטומטי מכתובת ה-IP של הבקשה),
  `source.host_name` (ריק = זיהוי אוטומטי מהמכונה המריצה)
- **Destination**: `destinations[0].http_request_url`, `destinations[0].http_request_url_hostname`

הערכים נשמרים בקובץ `data/settings.json` (נוצר אוטומטית, לא ב-git) ודורסים את ברירות המחדל מ-`.env`
עד לשינוי הבא. פרטי החיבור ל-Protector עצמו (`PROTECTOR_HOST/PORT/PROTOCOL/TOKEN` וכו') **לא**
ניתנים לשינוי דרך המסך הזה ונשארים אך ורק ב-`.env`, כדי שטעות הקלדה לא תשבית את השירות.

### הערה על HTTPS עם תעודת self-signed

יש שתי דרכים לתמוך בתעודת self-signed מול ה-Protector:

1. **מומלץ** — הגדירו `PROTECTOR_CA_CERT_PATH` לנתיב קובץ ה-CA (PEM). התעודה תאומת מולו.
2. **פחות מומלץ (מקביל ל-`curl -k`)** — הגדירו `PROTECTOR_TLS_REJECT_UNAUTHORIZED=false` כדי לדלג
   על אימות התעודה לחלוטין. השתמשו בזה רק בסביבת בדיקות.

## הרצה

```bash
npm start
```

השרת יאזין בכתובת `http://localhost:3000` (או הפורט שהוגדר ב-`PORT`). פתחו את הכתובת בדפדפן,
גררו קובץ (או לחצו לבחירה) ולחצו על "שליחה לבדיקה".

## התקנה כ-Windows Service (services.msc)

כדי להעביר את האפליקציה למחשב אחר ולהריץ אותה כשירות Windows (מופיע ב-`services.msc`,
עולה אוטומטית עם המחשב, ומתאושש לבד אם קורס) — הפרויקט כולל תמיכה מובנית דרך החבילה
[`node-windows`](https://www.npmjs.com/package/node-windows).

### שלבים במחשב היעד

1. **העתיקו את כל התיקייה** של הפרויקט למחשב היעד (כולל `package.json`, `server.js`, `src/`,
   `public/`, `scripts/`). **אין** צורך להעתיק את `node_modules/`, `.env`, `logs/`, `data/`
   או `daemon/` — אלה נוצרים מחדש בכל מחשב.
2. ודאו ש-[Node.js](https://nodejs.org/) מותקן במחשב היעד.
3. התקינו את התלויות:
   ```bash
   npm install
   ```
4. הגדירו את `.env` (ראו "הגדרת חיבור" למעלה) עם פרטי ה-Protector של הסביבה הזו.
5. **פתחו שורת פקודה כ-Administrator** (Run as administrator) — הרשמת שירות Windows דורשת
   הרשאות מוגברות — ומהתיקייה של הפרויקט הריצו:
   ```bash
   npm run service:install
   ```
   השירות ("DLP Protector Client") ייווצר ויופעל אוטומטית. אפשר לוודא זאת ב-`services.msc`
   או עם:
   ```powershell
   Get-Service -Name "DLP Protector Client"
   ```
6. השירות מוגדר לעלות אוטומטית עם המחשב (Automatic startup) ולהתאושש עד 3 פעמים אם הוא קורס.

### הסרת השירות

גם זו פעולה שדורשת שורת פקודה מורמת (Administrator):

```bash
npm run service:uninstall
```

### פתרון תקלות

התקנת השירות יוצרת תיקיית `daemon/` (לא ב-git) עם קובץ עטיפה (wrapper) וקבצי לוג
(`*.out.log`, `*.err.log`, `*.wrapper.log`) — שימושיים אם השירות לא עולה כמצופה. לוגי
הריצה של האפליקציה עצמה (סריקות, resolution, זמני תגובה) ממשיכים להיכתב כרגיל ל-
`logs/requests.log.jsonl` לפי `LOG_FILE_PATH`.

## מבנה הפרויקט

```
server.js                # Express app + endpoints POST /api/scan, GET/POST /api/settings
src/config.js            # טעינת קונפיגורציה מ-.env (חיבור ל-Protector)
src/settingsStore.js      # הגדרות בטוחות הניתנות לשינוי דרך ה-UI, נשמרות ב-data/settings.json
src/protectorClient.js   # בניית ושליחת בקשת ה-Inspection API ל-Protector
src/logger.js            # לוג JSON-lines של כל בקשה
public/index.html        # UI - עמוד יחיד, drag & drop + מסך הגדרות, ללא build step
public/docs.html          # תיעוד API פנימי (POST /api/scan, GET/POST /api/settings)
scripts/install-service.js    # רישום כ-Windows Service (services.msc) - דורש הרצה כ-Administrator
scripts/uninstall-service.js  # הסרת ה-Windows Service
postman/                 # Postman collection + הוראות בדיקה (גם מול האפליקציה וגם ישירות מול ה-Protector)
logs/requests.log.jsonl  # נוצר אוטומטית - לוג ריצה (timestamp, filename, size, resolution, elapsedMs)
data/settings.json       # נוצר אוטומטית - הגדרות שנשמרו דרך מסך ה-Settings
daemon/                  # נוצר אוטומטית ע"י node-windows בעת התקנת השירות - לא ב-git
```

## בדיקה עם Postman

ראו [`postman/README.md`](postman/README.md) — כולל Postman collection מוכן לבדיקת ה-API
של האפליקציה עצמה, וגם הוראות + קבצי דוגמה מוכנים לבדיקה **ישירה** מול ה-Protector
(עוקף את האפליקציה), כולל ה"עטיפה" המיוחדת של חלק הקובץ שהתגלתה תוך כדי האינטגרציה.

## אבטחה

- כל הקריאה בפועל ל-Protector (כתובת, פורט, טוקן) מתבצעת אך ורק מה-Backend דרך `.env` —
  לעולם לא נחשפת ל-Frontend/Browser.
- הקובץ המועלה מעובד לחלוטין ב-memory (Multer memory storage) ולא נכתב לדיסק בשום שלב.
- קיימת ולידציה על גודל קובץ מקסימלי (`MAX_FILE_SIZE_MB`) לפני שליחה בפועל ל-Protector.