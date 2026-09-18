"""Pure synthetic evidence tests; no privileged proc files, KVM or mounts."""

import copy
import unittest

import validate_shared_memory as v


def smaps(flags="rd wr mr mw me ac nh"):
    return (f"100000-200000 rw-p 00000000 00:00 0\n"
            "KernelPageSize: 4 kB\nMMUPageSize: 4 kB\n"
            "AnonHugePages: 0 kB\nFilePmdMapped: 0 kB\nShmemPmdMapped: 0 kB\n"
            f"Shared_Hugetlb: 0 kB\nPrivate_Hugetlb: 0 kB\nVmFlags: {flags}\n")


def anon_entry(pfn):
    return (1 << 63) | v.PM_EXCLUSIVE | pfn


def control(anomaly=True):
    observation = {"smaps": smaps(),
                   "pagemap": [anon_entry(i + 1) for i in range(v.CONTROL_PAGES)],
                   "kpageflags": [v.KPF_ANON | (v.KPF_KSM if anomaly else 0)] * v.CONTROL_PAGES,
                   "kpagecount": [1] * v.CONTROL_PAGES}
    return {"madv_unmergeable": True,
            "addresses": [0x100000 + i * v.PAGE for i in range(v.CONTROL_PAGES)],
            "samples": [observation, copy.deepcopy(observation)]}


class ControlTests(unittest.TestCase):
    def test_standard_and_detected_anomaly(self):
        self.assertEqual(v.classify_control(control(False)), "standard")
        self.assertEqual(v.classify_control(control()), v.ANON_KSM_ANOMALY)

    def test_requires_explicit_unmergeable_advice(self):
        evidence = control()
        evidence["madv_unmergeable"] = False
        with self.assertRaisesRegex(RuntimeError, "explicitly unmergeable"):
            v.classify_control(evidence)

    def test_rejects_mergeable_or_incomplete_smaps(self):
        for text in (smaps("rd wr mg"), smaps("rd wr ht"),
                     smaps().replace("VmFlags:", "Missing:"),
                     smaps().replace("KernelPageSize: 4", "KernelPageSize: 2048"),
                     smaps().replace("AnonHugePages: 0", "AnonHugePages: 4"), ""):
            with self.subTest(smaps=text):
                evidence = control()
                evidence["samples"][0]["smaps"] = text
                with self.assertRaises(RuntimeError):
                    v.classify_control(evidence)

    def test_rejects_invalid_control_ownership(self):
        for key, value in (("pagemap", anon_entry(1) & ~v.PM_EXCLUSIVE),
                           ("pagemap", anon_entry(1) | v.PM_FILE),
                           ("pagemap", 1 << 63),
                           ("pagemap", anon_entry(2)),
                           ("kpageflags", v.KPF_KSM),
                           ("kpageflags", v.KPF_ANON | v.KPF_KSM | (1 << 22)),
                           ("kpagecount", 2), ("kpagecount", 0)):
            with self.subTest(key=key, value=value):
                evidence = control()
                evidence["samples"][0][key][0] = value
                with self.assertRaises(RuntimeError):
                    v.classify_control(evidence)

    def test_rejects_mixed_and_changing_ksm_flags(self):
        evidence = control()
        evidence["samples"][0]["kpageflags"][0] &= ~v.KPF_KSM
        with self.assertRaisesRegex(RuntimeError, "inconsistent"):
            v.classify_control(evidence)
        evidence = control()
        evidence["samples"][1]["kpageflags"] = [v.KPF_ANON] * v.CONTROL_PAGES
        with self.assertRaisesRegex(RuntimeError, "unstable"):
            v.classify_control(evidence)

    def test_rejects_missing_or_migrated_observations(self):
        for mutate in (lambda e: e["samples"].pop(),
                       lambda e: e["samples"][0]["kpagecount"].pop(),
                       lambda e: e["samples"][1]["pagemap"].__setitem__(0, anon_entry(999))):
            evidence = control()
            mutate(evidence)
            with self.assertRaises(RuntimeError):
                v.classify_control(evidence)


class PageTests(unittest.TestCase):
    def classify(self, entry=None, flag=None, count=1, anomaly=True):
        mode = v.classify_control(control(anomaly))
        v.classify_pages([anon_entry(1000) if entry is None else entry],
                         [v.KPF_ANON | v.KPF_KSM if flag is None else flag],
                         [count], {0}, mode)

    def test_valid_cow_on_both_hosts(self):
        self.classify()
        self.classify(flag=v.KPF_ANON, anomaly=False)

    def test_standard_host_still_rejects_ksm(self):
        with self.assertRaisesRegex(RuntimeError, "inconsistent with host control"):
            self.classify(anomaly=False)

    def test_anomalous_host_rejects_inconsistent_cow_flags(self):
        with self.assertRaisesRegex(RuntimeError, "inconsistent with host control"):
            self.classify(flag=v.KPF_ANON)

    def test_anomaly_cannot_excuse_missing_ownership(self):
        for kwargs in ({"entry": anon_entry(1000) & ~v.PM_EXCLUSIVE},
                       {"entry": anon_entry(1000) | v.PM_FILE},
                       {"count": 2}, {"count": 0}, {"flag": v.KPF_KSM}):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.classify(**kwargs)

    def test_rejects_huge_zero_and_compound_private_pages(self):
        for bit in (7, 10, 15, 16, 17, 19, 20, 22, 23, 24, 26):
            with self.subTest(bit=bit), self.assertRaises(RuntimeError):
                self.classify(flag=v.KPF_ANON | v.KPF_KSM | (1 << bit))

    def test_rejects_aliased_cow_pfns_even_with_exclusive_bit(self):
        with self.assertRaisesRegex(RuntimeError, "aliased"):
            v.classify_pages([anon_entry(1000)] * 2, [v.KPF_ANON | v.KPF_KSM] * 2,
                             [1, 1], {0, 1}, v.classify_control(control()))

    def test_file_pages_are_strict_on_both_hosts(self):
        entry = (1 << 63) | v.PM_FILE | 1000
        for anomaly in (False, True):
            mode = v.classify_control(control(anomaly))
            # Large file folios mapped with ordinary PTEs remain supported.
            v.classify_pages([entry], [1 << 22], [2], set(), mode)
            for flag in (v.KPF_ANON, v.KPF_KSM, 1 << 17, 1 << 24):
                with self.subTest(anomaly=anomaly, flag=flag), self.assertRaises(RuntimeError):
                    v.classify_pages([entry], [flag], [2], set(), mode)

    def test_anonymous_page_outside_expected_cow_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "expected nonanonymous file"):
            v.classify_pages([anon_entry(1000)], [v.KPF_ANON | v.KPF_KSM], [1],
                             set(), v.classify_control(control()))

    def test_unknown_mode_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unvalidated"):
            v.classify_pages([anon_entry(1000)], [v.KPF_ANON], [1], {0}, "unknown")


if __name__ == "__main__":
    unittest.main()
