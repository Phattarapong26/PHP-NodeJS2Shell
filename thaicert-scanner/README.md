# ThaiCERT Scanner — Svelte + TypeScript + Tauri

แอปเดิมเป็นไฟล์ `GUI.html` ไฟล์เดียว (~7,000 บรรทัด รวม HTML/CSS/JS ไว้ด้วยกัน)
โปรเจกต์นี้แปลงเป็น **Svelte 5 + TypeScript + Vite + Tailwind** และห่อด้วย **Tauri v2** สำหรับใช้เป็นแอป desktop
โดย **หน้าตาและ `id` ของ element ทุกตัวยังเหมือนเดิม** เพื่อให้ logic เดิมผูกกับ DOM ได้แบบ 1:1

---

## 1. สถานะงาน

| รายการ | ผล |
|---|---|
| Type check (`svelte-check`) | 0 errors (22 a11y warnings — ดูหัวข้อ 7) |
| TypeScript (`tsc --noEmit`) | 0 errors |
| Production build | ผ่าน (`dist/` ~2.2 MB รวมฟอนต์และไอคอนทั้งหมด) |
| Runtime smoke test | ผ่าน: mount สำเร็จ, element ที่มี `id` 280 ตัว, **0 uncaught error** |
| Backend contract test | ผ่าน: ยิง `/api/cve-database`, `/api/my-ip`, `/api/profiles`, `/api/system/check-update` แล้ว sync profile ขึ้น header ได้ |
| Tauri `cargo build` | **ยังไม่ได้รัน** — สภาพแวดล้อมที่ใช้แปลงงานไม่มี Rust toolchain ต้องรันบนเครื่องคุณ (หัวข้อ 4) |

---

## 2. โครงสร้างโปรเจกต์

```
thaicert-scanner/
├─ index.html                  จุดเข้า Vite (mount #app)
├─ src/
│  ├─ main.ts                  entry: import ฟอนต์/ไอคอน + mount App
│  ├─ App.svelte               root shell + เรียก bootstrap() ครั้งเดียวหลัง mount
│  └─ lib/
│     ├─ components/           48 Svelte component (markup คัดจาก GUI.html แบบ 1:1)
│     │  ├─ layout/            AppHeader, AppFooter
│     │  ├─ scanner/           ScannerView + hero / radar / ขั้นตอนสแกน
│     │  ├─ results/           ตารางผลสแกน, tabs, filter
│     │  ├─ audit/             DeepAudit, runtime layer, VA findings, chain info
│     │  ├─ cve/               CVE catalog
│     │  ├─ profiles/          Profile drawer + ฟอร์ม (แยกเป็น 7 ส่วนย่อย)
│     │  ├─ modals/            Workflow, SystemUpdate
│     │  └─ common/            Toast, Tooltips (floating chart tooltip)
│     ├─ controllers/          ~5,400 บรรทัด TypeScript = JS เดิมทั้งหมด
│     │  ├─ bootstrap.ts       ลำดับ init (แทน window.onload เดิม)
│     │  ├─ dom.ts             ศูนย์รวม element reference ทั้งหมด
│     │  ├─ api.ts             re-export ของ core/api
│     │  ├─ actions.ts         delegated click actions (แทน inline onclick)
│     │  └─ network / scan / results / audit / charts / cve / profiles / reports / ports / shell / ui ...
│     ├─ core/api.ts           ★ จุดเดียวที่คุยกับ backend
│     ├─ types/app.ts          type ของ appState
│     ├─ styles/app.css        Tailwind layers + CSS เดิม 215 บรรทัด
│     └─ vendor/phosphor/      ไอคอนฟอนต์ (woff2 เท่านั้น)
├─ src-tauri/                  Rust shell + tauri.conf.json + capabilities + icons
├─ public/favicon.png
└─ scripts/smoke.mjs           runtime smoke test (jsdom)
```

### ลำดับ bootstrap (เหมือนของเดิม แต่ไม่ล้มกลางทางแล้ว)

`bindDom()` → `installActionDelegation()` → `initBindings()` → `initCve()` → `initShell()` →
`initReports()` → `initProfiles()` → `initSystemUpdate()` → `onAppLoad()`
(เรียกบน `onMount` ของ `App.svelte` ครั้งเดียว มี guard กัน double-init)

---

## 3. รันแบบ web / dev

```bash
npm install
cp .env.example .env      # ถ้าต้องการชี้ backend เอง
npm run dev               # http://localhost:1420 (proxy /api -> VITE_API_PROXY)
npm run build             # production build ลง dist/
npm run preview           # เปิด dist/ ดูแบบ local
npm run verify            # check + tsc + build + smoke test
```

---

## 4. รันเป็นแอป desktop (Tauri v2)

ต้องมี **Rust 1.77.2+**, WebView2 (Windows), Xcode CLI (macOS) หรือ webkit2gtk (Linux)

```bash
npm install
npm run tauri:dev         # เปิดหน้าต่างแอป + hot reload
npm run tauri:build       # ได้ installer ใน src-tauri/target/release/bundle/
```

ไฟล์ที่เกี่ยวข้อง:
- `src-tauri/tauri.conf.json` — window 1440x900, ชื่อแอป, ไอคอน, CSP
- `src-tauri/capabilities/default.json` — `core:default` + `opener:allow-open-url` (เปิดลิงก์ออกเบราว์เซอร์ระบบ)
- `src-tauri/icons/` — สร้างใหม่ครบทุกขนาด (png / ico / icns)

---

## 5. การเชื่อมต่อ backend (สำคัญ)

ทราฟฟิกทั้งหมดผ่าน `src/lib/core/api.ts` ที่เดียว ลำดับการเลือก base URL:

1. `localStorage["thaicert.apiBase"]` — override ตอนรัน (`setApiBase()`)
2. `VITE_API_BASE` จาก `.env`
3. ถ้าเป็น Tauri / `file:` / ไม่มี host → `http://localhost:5050`
4. ไม่งั้นใช้ same-origin (relative `/api/...` เหมือนเดิม)

### CSP ใน Tauri

`src-tauri/tauri.conf.json` ตั้ง `connect-src` ให้ `http://localhost:*` และ `http://127.0.0.1:*` ไว้แล้ว
**ถ้า backend อยู่เครื่องอื่น** (เช่น `http://192.168.1.10:5050`) ต้องเพิ่ม origin นั้นใน `connect-src` ด้วย
ไม่งั้น webview จะบล็อก request เอง

### ต้องแก้ฝั่ง backend เล็กน้อย

หลังบ้านต้องตอบ CORS ให้ origin ของแอป (`tauri://localhost`, บน Windows คือ `http://tauri.localhost`,
ตอน dev คือ `http://localhost:1420`) ถ้าเดิม backend เสิร์ฟหน้าเว็บเองอยู่แล้ว ให้เพิ่ม allowed origin เหล่านี้

---

## 6. สิ่งที่แก้ไของค์ประกอบเดิม (นอกจากการย้ายโค้ด)

1. **บั๊ก fatal ในโค้ดเดิม (แก้แล้ว)** — `GUI.html` บรรทัด 2753 เรียก
   `inputWorkerConcurrency.addEventListener(...)` โดยไม่มี guard แต่ `#inputWorkerConcurrency`
   ไม่มีอยู่ใน HTML เลย → `TypeError` ตอนโหลด และ **สคริปต์ทั้งหมดหลังจากนั้นไม่ถูกประมวลผล**
   รวมถึง `window.onload` (บรรทัด 5071) ทำให้ auto-detect เครือข่าย, การโหลด profile,
   tooltip/chart controls ไม่เคยทำงานในแอปเดิม
   *ยืนยันด้วยการรัน `GUI.html` เดิมใน jsdom: 1 uncaught error และ `window.onload` ไม่ถูก assign*
   ตอนนี้ใส่ guard แล้ว bootstrap ทำงานครบทุกขั้น
2. `onclick="..."` ที่ HTML สร้างจาก JS ถูกเปลี่ยนเป็น `data-action="..." data-arg="..."` + listener กลาง
   (`controllers/actions.ts`) เพราะ CSP ของ Tauri บล็อก inline handler — พฤติกรรมเหมือนเดิมทุกจุด
3. ลบ dead binding 3 ตัว (`btnCloseProfileModal`, `btnDoneProfileModal`, `profileSelectModal`)
   ที่อ้าง id ซึ่งไม่มีใน markup ตั้งแต่ต้น (ถูกแทนที่ด้วย `ProfileSelectDrawer`)
4. ไอคอน Phosphor ตัดเหลือเฉพาะ `woff2` (เดิม bundle ลาก `.svg`/`.ttf` มาด้วย)
5. ฟอนต์ (Plus Jakarta Sans, Sarabun) และไอคอน bundle เข้าแอป → ใช้ offline ได้ ไม่พึ่ง CDN

> Element ที่ `controllers` อ้างถึงแต่ไม่มีใน markup มี 54 ตัว (เช่น `settingsDrawer`, `inputStartPort`,
> `mainSubnetInput`) — เป็นโค้ด legacy ที่ตายอยู่แล้วในแอปเดิม ทุกจุดมี `if (...)` ครอบ จึงไม่มีผลต่อการทำงาน
> และคงไว้ตามต้นฉบับเพื่อไม่ให้ divergence

---

## 7. ข้อจำกัด / งานที่ควรต่อ

- **22 a11y warnings** จาก `svelte-check` (`<label>` ไม่ผูก control, ปุ่ม icon-only ไม่มี `aria-label`,
  `<div onclick>` ไม่มี role) — มาจาก markup ที่ยกมา 1:1 ยังไม่กระทบการทำงาน
- **ยังไม่ได้เทียบภาพแบบ pixel-perfect** — สภาพแวดล้อมที่ใช้ทำงานไม่มีเบราว์เซอร์จริง
  ที่ตรวจแล้วคือ DOM structure (280 id ตรงกัน), ไม่มี runtime error, และเส้นทาง fetch → state → render ทำงานจริง
  แนะนำให้ `npm run tauri:dev` แล้วเทียบกับ `GUI.html` อีกครั้ง
- `src-tauri` ยังไม่เคย compile ด้วย Rust จริงในสภาพแวดล้อมนี้
- ไม่มีไฟล์ `.env` จริงมาให้ (มีแต่ `.env.example`)

---

© ThaiCERT Scanner — internal tool
