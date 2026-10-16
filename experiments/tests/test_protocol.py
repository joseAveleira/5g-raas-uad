import sys
import unittest
from pathlib import Path
import numpy as np
import pandas as pd
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.data import candidate_repeats, temporal_split, feature_groups, forbidden_feature
from src.evaluation import model_pipeline


class ProtocolTests(unittest.TestCase):
    def test_target_name_guard_preserves_protocol_type_fields(self):
        self.assertTrue(forbidden_feature("type"))
        self.assertTrue(forbidden_feature("label"))
        self.assertTrue(forbidden_feature("frame_time_epoch_mean"))
        self.assertFalse(forbidden_feature("tls_record_content_type"))
        self.assertFalse(forbidden_feature("quic_long_packet_type"))

    def test_repeat_groups_are_anchor_bounded_and_ignore_label(self):
        raw=pd.DataFrame({"frame_time_epoch":[0,.0004,.0008,.0012],
                          "frame_number":[1,2,3,4],"label":[0,0,1,1],
                          "type":["normal","normal","attack","attack"],
                          "frame_len":[100]*4,"ip_id":["0x12"]*4})
        groups,_=candidate_repeats(raw,.001)
        np.testing.assert_array_equal(groups,[0,0,0,3])
        self.assertEqual(raw.groupby(groups).label.nunique().max(),2)

    def test_embargo_excludes_near_boundary_windows(self):
        w=pd.DataFrame({"start":[0,10,18,20,23,26],"end":[2,12,20,22,25,28],
                        "label":[0,1,1,0,0,1]})
        train,test=temporal_split(w,20,2)
        np.testing.assert_array_equal(train,[0,1])
        np.testing.assert_array_equal(test,[4,5])
        rt,rv=temporal_split(w,20,2,"reverse")
        np.testing.assert_array_equal(rt,test);np.testing.assert_array_equal(rv,train)

    def test_metadata_and_gtp_excluded_from_network_baseline(self):
        w=pd.DataFrame(columns=["window_id","start","end","label","block_id","n_rows",
                                "source_row_first","source_row_last","rate_records",
                                "size_mean","fraction_tcp","fraction_gtp","gtp_length_mean",
                                "opaque_fragment_fraction"])
        g=feature_groups(w)
        self.assertEqual(g["network"],["rate_records","size_mean","fraction_tcp"])
        self.assertNotIn("label",g["capture_context"])
        self.assertNotIn("start",g["capture_context"])
        self.assertIn("fraction_gtp",g["network_gtp_presence"])

    def test_prediction_does_not_refit_preprocessing(self):
        rng=np.random.default_rng(42)
        x=pd.DataFrame(rng.normal(size=(60,20)),columns=[f"x{i}" for i in range(20)])
        y=(x.x0>0).astype(int)
        p=model_pipeline("logistic",42,{"logistic_C":1},5).fit(x,y)
        means=p.named_steps["scale"].mean_.copy()
        selection=p.named_steps["select"].get_support().copy()
        p.predict_proba(x*1e6+1e9)
        np.testing.assert_array_equal(means,p.named_steps["scale"].mean_)
        np.testing.assert_array_equal(selection,p.named_steps["select"].get_support())


if __name__=="__main__": unittest.main()
