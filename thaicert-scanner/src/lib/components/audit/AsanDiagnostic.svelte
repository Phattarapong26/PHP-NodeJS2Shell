<!--
  @component AsanDiagnostic
  Markup ported 1:1 from the original GUI.html (lines 1084-1141).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import { runLiveAsanAudit } from '../../controllers/audit';
</script>

            <!-- Low-Level C & AddressSanitizer (ASan) Memory Diagnostic Module -->
            <div id="asanMemoryDiagnosticSection" class="pt-4 border-t border-slate-200/60 space-y-3">
              <div class="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h4 class="font-bold text-slate-800 text-xs sm:text-sm flex items-center gap-2">
                    <i class="ph-bold ph-cpu text-purple-600 text-base"></i>
                    การตรวจวัดระดับหน่วยความจำลึกและสถาปัตยกรรม Zend C (Low-Level C & ASan Memory Diagnostics)
                  </h4>
                  <span class="text-[10px] text-slate-400">วิเคราะห์ข้อผิดพลาดหน่วยความจำ Heap Use-After-Free ใน Zend Engine (var_unserializer.c:245/851), สถานะ BG(serialize_lock) และการตรวจจับ AddressSanitizer</span>
                </div>
                <button id="btnRunAsanAudit" onclick={() => runLiveAsanAudit()} class="px-3 py-1.5 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white text-[11px] font-bold flex items-center gap-1.5 shadow-xs transition cursor-pointer">
                  <i class="ph-bold ph-cpu"></i>
                  <span id="btnRunAsanAuditText">ตรวจสอบเงื่อนไขระดับ C / Zend Patch Advisory</span>
                </button>
              </div>

              <!-- C-Level Architecture Metrics Grid -->
              <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5" id="asanMetricsGrid">
                <div class="p-2.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                  <div class="text-[10px] text-slate-400 font-mono">Zend Core Source</div>
                  <div class="text-xs font-bold text-slate-800 mt-0.5" id="asanMetricSource">var_unserializer.c</div>
                  <div class="text-[9px] text-slate-500 font-mono mt-0.5">Lines: 245 (free) / 851 (read)</div>
                </div>
                <div class="p-2.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                  <div class="text-[10px] text-slate-400 font-mono">BG(serialize_lock)</div>
                  <div class="text-xs font-bold text-slate-800 mt-0.5" id="asanMetricLock">0 (Unprotected)</div>
                  <div class="text-[9px] text-slate-500 font-mono mt-0.5">Reentry Destructor Guard</div>
                </div>
                <div class="p-2.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                  <div class="text-[10px] text-slate-400 font-mono">VAR_ENTRIES_MAX Bound</div>
                  <div class="text-xs font-bold text-slate-800 mt-0.5" id="asanMetricChunk">> 1018 Entries</div>
                  <div class="text-[9px] text-slate-500 font-mono mt-0.5">Dynamic Heap Chunk Shift</div>
                </div>
                <div class="p-2.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                  <div class="text-[10px] text-slate-400 font-mono">Allocator Profile</div>
                  <div class="text-xs font-bold text-slate-800 mt-0.5" id="asanMetricAlloc">USE_ZEND_ALLOC=1</div>
                  <div class="text-[9px] text-slate-500 font-mono mt-0.5">ASan Exposed under =0</div>
                </div>
              </div>

              <!-- Interactive ASan Terminal Output Box -->
              <div class="p-3 rounded-2xl bg-slate-950 font-mono text-[11px] border border-slate-800 text-slate-300 shadow-inner space-y-2">
                <div class="flex items-center justify-between pb-2 border-b border-slate-800/80">
                  <div class="flex items-center gap-2">
                    <span class="inline-block w-2.5 h-2.5 rounded-full bg-rose-500/80"></span>
                    <span class="inline-block w-2.5 h-2.5 rounded-full bg-amber-500/80"></span>
                    <span class="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500/80"></span>
                    <span class="text-[10px] text-slate-400 ml-1">AddressSanitizer / Zend Engine Runtime Memory Inspector</span>
                  </div>
                  <span id="asanStatusPill" class="px-2 py-0.5 rounded text-[9px] font-bold bg-purple-900/60 text-purple-300 border border-purple-700/50">ASAN READY</span>
                </div>
                <div class="overflow-x-auto whitespace-pre leading-relaxed select-all text-[10.5px]" id="asanTerminalTrace">=================================================================
== AddressSanitizer & Zend Core Deep Diagnostic Subsystem ==
Target: Ready for Live Probe
กดปุ่ม "รันการทดสอบระดับ C / ASan Probe (Live)" เพื่อเริ่มการประเมินสถานะหน่วยความจำระดับ C Code และ AddressSanitizer แบบเรียลไทม์
=================================================================</div>
              </div>
            </div>
