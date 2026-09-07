from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wechat_ai_exporter.transcription import LocalVoiceTranscriber, VoiceRuntimeError


class TranscriptionTests(unittest.TestCase):
    @staticmethod
    def _runtime(root: Path) -> Path:
        runtime = root / "voice-runtime"
        for relative in (
            "silk/silk-decoder.exe", "whisper/whisper-cli.exe", "models/ggml-base.bin"
        ):
            path = runtime / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"test")
        return runtime

    def test_missing_runtime_is_reported_before_export(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            transcriber = LocalVoiceTranscriber(Path(temp))
            with self.assertRaises(VoiceRuntimeError):
                transcriber.validate()

    def test_decode_and_offline_recognition_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = self._runtime(root)
            silk = root / "voice.silk"
            silk.write_bytes(b"#!SILK_V3test")

            def fake_run(command, **_kwargs):
                if Path(command[0]).name == "silk-decoder.exe":
                    Path(command[2]).write_bytes(b"\x00\x00" * 1600)
                else:
                    prefix = Path(command[command.index("-of") + 1])
                    prefix.with_suffix(".txt").write_text(
                        "  你好，离线转写成功。\n", encoding="utf-8"
                    )
                return subprocess.CompletedProcess(command, 0, b"", b"")

            with patch("wechat_ai_exporter.transcription.subprocess.run", fake_run):
                result = LocalVoiceTranscriber(runtime).transcribe(silk)
            self.assertEqual(result.status, "transcribed")
            self.assertEqual(result.text, "你好，离线转写成功。")
            self.assertEqual(result.language, "zh")


if __name__ == "__main__":
    unittest.main()
