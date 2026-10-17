import io
import json
import unittest
from unittest.mock import Mock, patch

from bugbounty_toolkit.analysis.evidence_review import review_evidence
from bugbounty_toolkit.analysis.ollama_review import OLLAMA_CHAT_URL, review_with_ollama


class OllamaReviewTests(unittest.TestCase):
    def test_only_sanitized_packet_is_sent_to_fixed_local_endpoint(self):
        source = {
            "type": "access-control",
            "steps": [{"step": "cross_read", "status_code": 200, "owner_resource_match": True}],
            "raw_url": "https://private.example/objects/secret-id?token=secret-token",
            "body": "private response body",
        }
        packet = review_evidence(source)
        assessment = {"decision": "candidate", "summary": "Review required.",
                      "evidence": ["A crossed response matched configured predicates."],
                      "limitations": ["Account ownership still needs verification."]}
        envelope = {"message": {"content": json.dumps(assessment)}}
        opener = Mock()
        opener.open.return_value = io.BytesIO(json.dumps(envelope).encode("utf-8"))
        with patch("bugbounty_toolkit.analysis.ollama_review.build_opener", return_value=opener):
            result = review_with_ollama(packet, "llama3.2:3b")
        request = opener.open.call_args.args[0]
        sent = request.data.decode("utf-8")
        self.assertEqual(request.full_url, OLLAMA_CHAT_URL)
        self.assertNotIn("private.example", sent)
        self.assertNotIn("secret-id", sent)
        self.assertNotIn("secret-token", sent)
        self.assertNotIn("private response body", sent)
        self.assertNotIn("tools", json.loads(sent))
        self.assertEqual(result["assessment"], assessment)
        self.assertTrue(result["raw_evidence_sent"] is False)
        self.assertEqual(result["request_destination"], "127.0.0.1:11434")

    def test_rejects_invalid_model_packets_and_model_output(self):
        packet = review_evidence({"type": "xss", "results": []})
        for model in ("http://remote.invalid/model", "bad model", ""):
            with self.subTest(model=model), self.assertRaises(ValueError):
                review_with_ollama(packet, model)
        with self.assertRaises(ValueError):
            review_with_ollama({"type": "xss", "results": []}, "llama3.2")

        opener = Mock()
        opener.open.return_value = io.BytesIO(b'{"message":{"content":"not json"}}')
        with patch("bugbounty_toolkit.analysis.ollama_review.build_opener", return_value=opener):
            with self.assertRaises(ValueError):
                review_with_ollama(packet, "llama3.2")
