from cape_audit import CapeDynamicTestBase, CapeTestObjective, OSTarget
from cape_audit.verifiers import (VerifyReportSectionHasMatching, VerifyReportSectionHasContent, VerifyReportHasExactString)


class CapeDynamicTest(CapeDynamicTestBase):
    def __init__(self):
        super().__init__(test_name="Guloader Bypass", analysis_package="exe")
        self.set_description("Tests dynamic Guloader anti bypass")
        self.set_zip_password(None)
        self.set_task_timeout_seconds(30)
        self.set_os_targets([OSTarget.WINDOWS])
        self.set_enforce_timeout(False)
        self.set_task_config({
              "Route": None,
              "Tags": [ "win10","x64"],
              "Request Options": "",
              "Custom Request Params": None
          })
        self._init_objectives()

    def _init_objectives(self):
        
        # check if there are any behavioural listings at all in the report
        o_has_behaviour_trace = CapeTestObjective(test=self, requirement="API calls are being hooked", objective_name="BehaviourInfoGenerated")
        o_has_behaviour_trace.set_success_msg("Behavioral output from API hooks detected")
        o_has_behaviour_trace.set_failure_msg("There may be a detonation problem, expected behavior log not found")
        o_has_behaviour_trace.set_result_verifier(VerifyReportSectionHasContent("behavior"))
        self.add_objective(o_has_behaviour_trace)

        # check if it caught the network comms
        o_comms = CapeTestObjective(test=self, requirement="Malware comms detected to known CNC domain", objective_name="DetectComms", is_informational=False)
        o_comms.set_success_msg("Malware comms detected")
        o_comms.set_failure_msg("There may be a detonation problem, expected network comms not detected")
        evaluator = VerifyReportSectionHasMatching(path="behavior/processes/calls", match_criteria={"api": "GetAddrInfoExW", "arguments/value": "bara-seck.com"})
        o_comms.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_comms)

        # check breakpoint(s) hit
        o_breakpoint = CapeTestObjective(test=self, requirement="Breakpoint(s) hit", objective_name="DetectBreakpointHits", is_informational=False)
        o_breakpoint.set_success_msg("CAPE intercepted breakpoint(s)")
        o_breakpoint.set_failure_msg("There may be a problem with breakpoints not hitting")
        o_breakpoint.set_result_verifier(VerifyReportHasExactString("CAPEExceptionFilter: breakpoint 3 hit"))
        o_has_behaviour_trace.add_child_objective(o_breakpoint)


if __name__ == "__main__":
    mytest = CapeDynamicTest()
    # developers: change me
    mytest.evaluate_results(r"[path_to_task_store_dir_after_payload_analysis]")
    mytest.print_test_results()
