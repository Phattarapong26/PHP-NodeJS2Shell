<!--
  @component ProbeInspectionLog
  Markup ported 1:1 from the original GUI.html (lines 1143-1224).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
            <!-- Probe Inspection Log & Response Evidence Section -->
            <div id="auditProbeLogSection" class="pt-4 border-t border-slate-200/60 space-y-3">
              <div class="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h4 class="font-bold text-slate-800 text-xs sm:text-sm flex items-center gap-2">
                    <i class="ph-bold ph-terminal-window text-indigo-600 text-base"></i>
                    บันทึกคำขอตรวจสอบและการตอบสนอง (Audit Probe & Target Response Log)
                  </h4>
                  <span class="text-[10px] text-slate-400">แสดงข้อมูลทางเทคนิคของคำขอตรวจสอบเชิงรับ (Passive Probe) และผลการตอบสนองที่ได้รับจริง</span>
                </div>
                <div class="flex items-center gap-1.5">
                  <span id="probeMethodBadge" class="px-2 py-0.5 rounded-md font-mono text-[10px] font-bold bg-blue-600 text-white">GET</span>
                  <span id="probeStatusCode" class="px-2 py-0.5 rounded-md font-mono text-[10px] font-bold bg-emerald-600 text-white">200 OK</span>
                  <span id="probeLatency" class="px-2 py-0.5 rounded-md font-mono text-[10px] bg-slate-100 text-slate-700 border border-slate-200">1.2 ms</span>
                </div>
              </div>

              <!-- Main Probe Breakdown Grid -->
              <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <!-- Col 1: คำขอที่ส่งออกไป (Request Dispatched) -->
                <div class="p-3.5 rounded-2xl bg-white border border-slate-200/90 shadow-xs space-y-2.5">
                  <div class="flex items-center justify-between pb-2 border-b border-slate-100">
                    <span class="text-xs font-bold text-slate-700 flex items-center gap-1.5">
                      <i class="ph-bold ph-paper-plane-tilt text-blue-600"></i> คำขอตรวจสอบเชิงรับ (Passive Audit Probe)
                    </span>
                    <span class="text-[10px] font-mono text-slate-400">Non-destructive</span>
                  </div>

                  <div class="space-y-1.5 text-xs">
                    <div>
                      <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Target Endpoint URL:</span>
                      <span id="probeTargetUrl" class="font-mono text-[11px] text-indigo-600 font-semibold break-all">http://...</span>
                    </div>
                    <div>
                      <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">กลยุทธ์การตรวจสอบ (Audit Strategy):</span>
                      <span id="probeAuditStrategy" class="text-slate-700 text-[11px]">การตรวจสอบเชิงรับแบบไม่ก่อกวนการทำงาน (Passive Signature & Security Header Probe)</span>
                    </div>
                    <div>
                      <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">ส่วนหัวคำขอที่ส่งไป (Request Headers):</span>
                      <div id="probeReqHeadersBox" class="p-2.5 rounded-xl bg-slate-950 font-mono text-[10px] text-slate-300 border border-slate-800 overflow-x-auto whitespace-pre leading-relaxed select-all">User-Agent: ThaiCERT-OPScaner/2.0 (LAN Discovery & Security Audit)
Accept-Encoding: br, gzip, deflate
Connection: keep-alive</div>
                    </div>
                  </div>
                </div>

                <!-- Col 2: ผลลัพธ์การตอบสนองที่ได้รับ (Response Received) -->
                <div class="p-3.5 rounded-2xl bg-white border border-slate-200/90 shadow-xs space-y-2.5">
                  <div class="flex items-center justify-between pb-2 border-b border-slate-100">
                    <span class="text-xs font-bold text-slate-700 flex items-center gap-1.5">
                      <i class="ph-bold ph-arrow-u-down-left text-emerald-600"></i> ผลการตอบสนองจากเป้าหมาย (Target Response Result)
                    </span>
                    <span id="probeStatusTextBadge" class="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">HTTP 200 OK</span>
                  </div>

                  <div class="space-y-1.5 text-xs">
                    <div>
                      <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">ส่วนหัวที่ได้รับกลับมา (Response Headers):</span>
                      <div id="probeRespHeadersBox" class="p-2.5 rounded-xl bg-slate-950 font-mono text-[10px] text-emerald-400 border border-slate-800 overflow-x-auto whitespace-pre leading-relaxed max-h-36 overflow-y-auto select-all">Server: Apache/2.4.58 (Ubuntu)
X-Powered-By: PHP/8.2.19
Content-Type: text/html; charset=UTF-8</div>
                    </div>
                    <div>
                      <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">หลักฐานเชิงเทคนิคที่ตรวจพบ (Forensic Evidence Indicators):</span>
                      <div id="probeEvidenceTags" class="flex flex-wrap gap-1.5">
                        <!-- Populated with tags -->
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Probe Steps Flow Timeline -->
              <div class="p-3.5 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-2">
                <span class="text-xs font-bold text-slate-700 flex items-center gap-1.5">
                  <i class="ph-bold ph-git-commit text-indigo-600"></i> ลำดับขั้นตอนการตรวจสอบจริง (Probe Execution Flow):
                </span>
                <div id="probeStepsContainer" class="space-y-1.5">
                  <!-- Dynamically populated steps -->
                </div>
              </div>
            </div>
