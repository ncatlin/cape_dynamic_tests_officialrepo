from cape_audit import CapeDynamicTestBase, CapeTestObjective, OSTarget
from cape_audit.verifiers import (VerifyReportSectionHasMatching, VerifyReportSectionHasContent, VerifyReportHasExactString)


class CapeDynamicTest(CapeDynamicTestBase):
    def __init__(self):
        super().__init__(test_name="Formbook Dynamic Config Extraction", analysis_package="exe")
        self.set_description("Tests Formbook dynamic config extraction")
        self.set_zip_password(None)
        self.set_task_timeout_seconds(200)
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

        # check there is a config containing C2
        o_config = CapeTestObjective(test=self, requirement="Config extracted dynamically contains malware C2", objective_name="DetectConfig", is_informational=False)
        o_config.set_success_msg("Config extracted")
        o_config.set_failure_msg("There may be an extraction problem, expected config not detected")
        evaluator = VerifyReportSectionHasMatching(path="CAPE/configs", match_criteria={"Formbook/C2": "www.riboute.com"})
        o_config.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_config)

        # check breakpoint(s) hit
        o_breakpoint = CapeTestObjective(test=self, requirement="Breakpoint(s) hit", objective_name="DetectBreakpointHits", is_informational=False)
        o_breakpoint.set_success_msg("CAPE intercepted breakpoint(s)")
        o_breakpoint.set_failure_msg("There may be a problem with breakpoints not hitting")
        o_breakpoint.set_result_verifier(VerifyReportHasExactString("CAPEExceptionFilter: breakpoint 2 hit"))
        o_has_behaviour_trace.add_child_objective(o_breakpoint)


if __name__ == "__main__":
    mytest = CapeDynamicTest()
    # developers: change me
    mytest.evaluate_results(r"[path_to_task_store_dir_after_payload_analysis]")
    mytest.print_test_results()
