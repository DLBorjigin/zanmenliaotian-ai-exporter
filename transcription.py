from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import tempfile
import wave


@dataclass(frozen=True)
class TranscriptionResult:
    status: str
    text: str | None = None
    engine: str = "whisper.cpp"
    model: str = "ggml-base"
    language: str = "zh"


class VoiceRuntimeError(RuntimeError):
    pass


def default_voice_runtime() -> Path:
    """Return the release-bundled voice runtime location."""
    return Path(__file__).resolve().parents[2] / "voice-runtime"


class LocalVoiceTranscriber:
    """Decode WeChat SILK and run whisper.cpp without network access."""

    def __init__(self, runtime: Path | None = None, language: str = "zh",
                 timeout_seconds: float = 300.0) -> None:
        self.runtime = (runtime or default_voice_runtime()).resolve(strict=False)
        self.language = language.strip() or "zh"
        self.timeout_seconds = max(5.0, min(float(timeout_seconds), 1800.0))
        self.decoder = self.runtime / "silk" / "silk-decoder.exe"
        self.whisper = self.runtime / "whisper" / "whisper-cli.exe"
        self.model = self.runtime / "models" / "ggml-base.bin"

    def missing_components(self) -> list[str]:
        return [
            path.relative_to(self.runtime).as_posix()
            for path in (self.decoder, self.whisper, self.model)
            if not path.is_file()
        ]

    def validate(self) -> None:
        missing = self.missing_components()
        if missing:
            raise VoiceRuntimeError(
                "The bundled offline voice runtime is incomplete: " + ", ".join(missing)
            )

    @staticmethod
    def _creation_flags() -> int:
        return int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if os.name == "nt" else 0

    @staticmethod
    def _write_wav(pcm: Path, wav_path: Path) -> None:
        data = pcm.read_bytes()
        if not data or len(data) % 2:
            raise ValueError("decoder produced invalid 16-bit PCM")
        with wave.open(str(wav_path), "wb") as output:
            output.setnchannels(1)
            output.setsampwidth(2)
            output.setframerate(16000)
            output.writeframes(data)

    @staticmethod
    def _clean_text(value: str) -> str:
        value = value.replace("\ufeff", "").replace("\x00", " ")
        return re.sub(r"\s+", " ", value).strip()

    def transcribe(self, silk_path: Path) -> TranscriptionResult:
        silk_path = silk_path.resolve(strict=False)
        if self.missing_components():
            return TranscriptionResult(
                status="runtime_missing", language=self.language
            )
        try:
            with tempfile.TemporaryDirectory(prefix="wechat-voice-asr-") as temporary:
                work = Path(temporary)
                pcm = work / "voice.pcm"
                wav_path = work / "voice.wav"
                output_prefix = work / "transcript"
                decoded = subprocess.run(
                    [str(self.decoder), str(silk_path), str(pcm),
                     "-Fs_API", "16000", "-quiet"],
                    cwd=self.decoder.parent, capture_output=True,
                    timeout=self.timeout_seconds, creationflags=self._creation_flags(),
                )
                if decoded.returncode != 0 or not pcm.is_file() or pcm.stat().st_size == 0:
                    return TranscriptionResult(
                        status="decoder_failed", language=self.language
                    )
                self._write_wav(pcm, wav_path)
                recognized = subprocess.run(
                    [str(self.whisper), "-m", str(self.model), "-f", str(wav_path),
                     "-l", self.language, "-otxt", "-of", str(output_prefix),
                     "-nt", "-np", "-ng"],
                    cwd=self.whisper.parent, capture_output=True,
                    timeout=self.timeout_seconds, creationflags=self._creation_flags(),
                )
                text_path = output_prefix.with_suffix(".txt")
                if recognized.returncode != 0 or not text_path.is_file():
                    return TranscriptionResult(
                        status="recognizer_failed", language=self.language
                    )
                text = self._clean_text(text_path.read_text(encoding="utf-8-sig"))
                if not text:
                    return TranscriptionResult(
                        status="empty_transcript", language=self.language
                    )
                return TranscriptionResult(
                    status="transcribed", text=text, language=self.language
                )
        except subprocess.TimeoutExpired:
            return TranscriptionResult(status="timeout", language=self.language)
        except (OSError, ValueError, UnicodeError):
            return TranscriptionResult(status="transcription_failed", language=self.language)
