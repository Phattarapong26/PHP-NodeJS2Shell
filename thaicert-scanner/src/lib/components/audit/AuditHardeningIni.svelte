<!--
  @component AuditHardeningIni
  Markup ported 1:1 from the original GUI.html (lines 1055-1082).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import { copyHardeningIni } from '../../controllers/audit';
</script>

            <!-- Hardening Directives (php.ini) with 1-Click Copy -->
            <div class="pt-3 border-t border-slate-200/60 space-y-2">
              <div class="flex items-center justify-between mb-1">
                <span class="font-bold text-slate-700 text-[11px] flex items-center gap-1">
                  <i class="ph-bold ph-file-code text-indigo-600"></i> แนวทางปรับปรุงค่า php.ini เพื่อความปลอดภัย (Hardening Directives):
                </span>
                <button id="btnCopyHardeningIni" onclick={() => copyHardeningIni()} class="px-2.5 py-1 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-[10px] font-semibold flex items-center gap-1 transition cursor-pointer">
                  <i class="ph-bold ph-copy"></i>
                  <span id="copyIniBtnText">คัดลอก php.ini Hardening</span>
                </button>
              </div>
              <div class="p-2.5 rounded-xl bg-slate-900 font-mono text-[11px] text-emerald-400 border border-slate-800 select-all overflow-x-auto whitespace-pre leading-relaxed" id="hardeningIniCodeBox">; [Chain B Defense: ปิดกั้นการเปิดเผยข้อมูลสภาพแวดล้อม]
expose_php = Off
display_errors = Off
log_errors = On

; [Chain A Defense: ป้องกันการสร้างข้อมูลเซสชันแฝงผ่าน Upload Progress]
session.upload_progress.enabled = Off
session.upload_progress.cleanup = On
session.use_strict_mode = 1

; [Chain C Defense: ป้องกันความไม่สอดคล้องของ Serializer และ Object Deserialization]
session.serialize_handler = php

; [Chain D Defense: ควบคุมการใช้หน่วยความจำและแยกพื้นที่จัดเก็บเซสชัน]
memory_limit = 256M
session.save_path = "/var/lib/php/sessions"</div>
            </div>
