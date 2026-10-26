# ---------------------------------------------------------------------------
# 1. Imports and env loading
# ---------------------------------------------------------------------------
import json
import os
import re
import secrets
import tempfile
import asyncio
import hashlib
import mimetypes
import uuid
import zipfile
from urllib.parse import urlparse

import boto3
import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Form, Response
from groq import AsyncGroq
from PIL import Image
import winocr
import pypdf
from twilio.rest import Client as TwilioClient
from twilio.twiml.messaging_response import MessagingResponse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

REQUIRED_ENV = [
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_WHATSAPP_NUMBER",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_REGION",
    "S3_BUCKET_NAME",
    "VIRUSTOTAL_API_KEY",
    "GROQ_API_KEY",
]
_missing = [k for k in REQUIRED_ENV if not os.getenv(k, "").strip()]
if _missing:
    print(f"WARNING: missing env variables: {', '.join(_missing)}")
if os.getenv("TWILIO_WHATSAPP_NUMBER") and not os.getenv("TWILIO_WHATSAPP_NUMBER").startswith("whatsapp:"):
    print("WARNING: TWILIO_WHATSAPP_NUMBER should look like 'whatsapp:+1415...'")

GROQ_MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")
WHISPER_MODEL = os.getenv("WHISPER_MODEL", "whisper-large-v3-turbo")
SANDBOX_JOIN_PHRASE = os.getenv("TWILIO_SANDBOX_JOIN", "join twilio-trial")
groq_client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))

twilio_client = TwilioClient(os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTH_TOKEN"))

s3_client = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION", "us-east-1"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

transcribe_client = boto3.client(
    "transcribe",
    region_name=os.getenv("AWS_REGION", "us-east-1"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

app = FastAPI()


# ---------------------------------------------------------------------------
# 2. Rule engine
# ---------------------------------------------------------------------------
with open(os.path.join(BASE_DIR, "rules.json"), encoding="utf-8") as f:
    RULES = json.load(f)


def run_rules(text: str):
    """Return the first rule whose pattern matches text (case-insensitive), else None."""
    if not text:
        return None
    for rule in RULES:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            return rule
    return None


def rule_verdict(text: str):
    rule = run_rules(text)
    if rule and float(rule["confidence"]) >= 0.85:
        return {
            "verdict": rule["label"],
            "confidence": rule["confidence"],
            "reason": rule["reason"],
        }
    return None


# ---------------------------------------------------------------------------
# 3. VirusTotal file scan
# ---------------------------------------------------------------------------
def _vt_stats(stats: dict) -> dict:
    stats = stats or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "verdict": "SCAM" if malicious > 0 else "CLEAN",
    }


async def scan_file_virustotal(filepath: str) -> dict:
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY", "")}
    with open(filepath, "rb") as fh:
        sha256 = hashlib.sha256(fh.read()).hexdigest()

    async with httpx.AsyncClient(timeout=60) as client:
        # Fast path: file already known to VirusTotal (no upload, no polling)
        r = await client.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers)
        if r.status_code == 200:
            return _vt_stats(r.json()["data"]["attributes"].get("last_analysis_stats", {}))

        with open(filepath, "rb") as fh:
            resp = await client.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files={"file": (os.path.basename(filepath), fh)},
            )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        attrs = {}
        for _ in range(10):  # 10 x 3s = 30 seconds
            await asyncio.sleep(3)
            r = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            )
            r.raise_for_status()
            attrs = r.json()["data"]["attributes"]
            if attrs.get("status") == "completed":
                break

    return _vt_stats(attrs.get("stats", {}))


# ---------------------------------------------------------------------------
# 4. APK detection
# ---------------------------------------------------------------------------
APK_MIME = "application/vnd.android.package-archive"


def is_apk(filepath: str, content_type: str = "") -> bool:
    if content_type.lower() == APK_MIME or filepath.lower().endswith(".apk"):
        return True
    if not zipfile.is_zipfile(filepath):
        return False
    try:
        with zipfile.ZipFile(filepath) as zf:
            names = set(zf.namelist())
        return "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names)
    except zipfile.BadZipFile:
        return False


# ---------------------------------------------------------------------------
# 5. Media downloader
# ---------------------------------------------------------------------------
async def download_media(media_url: str, dest_dir: str, content_type: str = "") -> str:
    name = os.path.basename(urlparse(media_url).path) or "attachment"
    ext = mimetypes.guess_extension(content_type.split(";")[0].strip()) if content_type else None
    if content_type.lower() == APK_MIME:
        ext = ".apk"
    elif content_type.lower() == "application/pdf":
        ext = ".pdf"
    if ext and not name.lower().endswith(ext):
        name += ext
    filepath = os.path.join(dest_dir, name)
    auth = (os.getenv("TWILIO_ACCOUNT_SID", ""), os.getenv("TWILIO_AUTH_TOKEN", ""))
    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        resp = await client.get(media_url, auth=auth)
        resp.raise_for_status()
        with open(filepath, "wb") as fh:
            fh.write(resp.content)
    return filepath


# ---------------------------------------------------------------------------
# 6. OCR and Document Text Extractors
# ---------------------------------------------------------------------------
def _ocr_pil_sync(filepath: str) -> str:
    try:
        with Image.open(filepath) as img:
            res = winocr.recognize_pil_sync(img)
            return (res.get("text") or "").strip()
    except Exception as e:
        print(f"ERROR _ocr_pil_sync: {e}")
        return ""


async def extract_image_text(filepath: str) -> str:
    return await asyncio.to_thread(_ocr_pil_sync, filepath)


def _extract_pdf_sync(filepath: str) -> str:
    text_chunks = []
    try:
        with open(filepath, "rb") as f:
            reader = pypdf.PdfReader(f)
            for page in reader.pages[:10]:
                t = page.extract_text()
                if t:
                    text_chunks.append(t)
    except Exception as e:
        print(f"ERROR _extract_pdf_sync: {e}")
    return "\n".join(text_chunks).strip()


async def extract_pdf_text(filepath: str) -> str:
    return await asyncio.to_thread(_extract_pdf_sync, filepath)


# ---------------------------------------------------------------------------
# 7. Languages (English / Hindi / Gujarati / Marathi)
# ---------------------------------------------------------------------------
LANGS = ("en", "hi", "gu", "mr")
LANG_NAMES_EN = {"en": "English", "hi": "Hindi", "gu": "Gujarati", "mr": "Marathi"}

STRINGS = {
    "en": {
        "title": "🔍 Scam Detection Result",
        "verdict": "Verdict",
        "confidence": "Confidence",
        "reason": "Reason",
        "heard": "🎙️ Transcript",
        "verdicts": {"SCAM": "SCAM ❌", "CLEAN": "CLEAN ✅", "SUSPICIOUS": "SUSPICIOUS ⚠️", "UNKNOWN": "UNKNOWN ❓"},
        "fin_alert": "🚨 *Financial Alert:* This message involves money or payment requests. Do NOT transfer funds or share bank/OTP details.",
        "failed": "⚠️ Analysis failed. Please try again.",
        "working": "⏳ Analyzing your file, result coming shortly...",
    },
    "hi": {
        "title": "🔍 स्कैम जांच परिणाम",
        "verdict": "निर्णय",
        "confidence": "भरोसा",
        "reason": "कारण",
        "heard": "🎙️ आवाज़ का टेक्स्ट",
        "verdicts": {"SCAM": "धोखाधड़ी ❌", "CLEAN": "सुरक्षित ✅", "SUSPICIOUS": "संदिग्ध ⚠️", "UNKNOWN": "अज्ञात ❓"},
        "fin_alert": "🚨 *वित्तीय चेतावनी:* इस संदेश में पैसे या भुगतान की मांग है। पैसे ट्रांसफर न करें और बैंक/OTP की जानकारी साझा न करें।",
        "failed": "⚠️ विश्लेषण विफल रहा। कृपया फिर से प्रयास करें।",
        "working": "⏳ आपकी फ़ाइल की जांच हो रही है, परिणाम जल्द आएगा...",
    },
    "gu": {
        "title": "🔍 સ્કેમ તપાસ પરિણામ",
        "verdict": "નિર્ણય",
        "confidence": "વિશ્વાસ",
        "reason": "કારણ",
        "heard": "🎙️ અવાજનો ટેક્સ્ટ",
        "verdicts": {"SCAM": "છેતરપિંડી ❌", "CLEAN": "સુરક્ષિત ✅", "SUSPICIOUS": "શંકાસ્પદ ⚠️", "UNKNOWN": "અજ્ઞાત ❓"},
        "fin_alert": "🚨 *નાણાકીય ચેતવણી:* આ સંદેશમાં પૈસા અથવા ચુકવણીની માંગ છે. પૈસા ટ્રાન્સફર કરશો નહીં અને બેંક/OTP ની માહિતી શેર કરશો નહીં.",
        "failed": "⚠️ વિશ્લેષણ નિષ્ફળ ગયું. કૃપા કરીને ફરી પ્રયાસ કરો.",
        "working": "⏳ તમારી ફાઇલની તપાસ ચાલુ છે, પરિણામ ટૂંક સમયમાં આવશે...",
    },
    "mr": {
        "title": "🔍 स्कॅम तपासणी निकाल",
        "verdict": "निष्कर्ष",
        "confidence": "खात्री",
        "reason": "कारण",
        "heard": "🎙️ आवाजाचा मजकूर",
        "verdicts": {"SCAM": "फसवणूक ❌", "CLEAN": "सुरक्षित ✅", "SUSPICIOUS": "संशयास्पद ⚠️", "UNKNOWN": "अज्ञात ❓"},
        "fin_alert": "🚨 *आर्थिक इशारा:* या संदेशात पैशांची किंवा पेमेंटची मागणी आहे. पैसे पाठवू नका आणि बँक/OTP ची माहिती शेअर करू नका.",
        "failed": "⚠️ विश्लेषण अयशस्वी झाले. कृपया पुन्हा प्रयत्न करा.",
        "working": "⏳ तुमच्या फाइलची तपासणी सुरू आहे, निकाल लवकरच येईल...",
    },
}

_GUJARATI_RE = re.compile(r"[\u0A80-\u0AFF]")
_DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")
_DEVANAGARI_WORD_RE = re.compile(r"[\u0900-\u097F]+")

# Hindi and Marathi share a script, so tell them apart by common function words.
_MARATHI_WORDS = {
    "आहे", "आहेत", "नाही", "आणि", "तुमचा", "तुमची", "तुमचे", "तुमच्या", "तुम्ही", "मला",
    "आम्ही", "करा", "पाठवा", "झाले", "झाला", "होते", "काय", "आपण", "साठी", "खात्यात",
}
_HINDI_WORDS = {
    "है", "हैं", "नहीं", "और", "आपका", "आपकी", "आपके", "करें", "मुझे", "हम", "था", "थी",
    "रहा", "रही", "कि", "के", "का", "की", "को", "से", "पर", "में",
}


def detect_language(text: str, hint: str = None) -> str:
    """Return one of en/hi/gu/mr. Script wins; `hint` (LLM/Whisper guess) breaks ties."""
    hint = (hint or "").lower()[:2]
    text = text or ""
    if _GUJARATI_RE.search(text):
        return "gu"
    if _DEVANAGARI_RE.search(text):
        words = _DEVANAGARI_WORD_RE.findall(text)
        mr = sum(1 for w in words if w in _MARATHI_WORDS)
        hi = sum(1 for w in words if w in _HINDI_WORDS)
        if mr > hi:
            return "mr"
        if hi > mr:
            return "hi"
        return hint if hint in ("hi", "mr") else "hi"
    return hint if hint in LANGS else "en"


def determine_message_language(text: str, audio_hint: str = None) -> str:
    """Accurately determine target language for audio or text among en/hi/gu/mr."""
    audio_hint = (audio_hint or "").lower()[:2]
    text = text or ""
    # 1. Gujarati script is 100% conclusive
    if _GUJARATI_RE.search(text):
        return "gu"
    # 2. Audio hint for Gujarati
    if audio_hint == "gu":
        return "gu"
    # 3. Devanagari script: distinguish Marathi vs Hindi
    if _DEVANAGARI_RE.search(text):
        words = _DEVANAGARI_WORD_RE.findall(text)
        mr = sum(1 for w in words if w in _MARATHI_WORDS)
        hi = sum(1 for w in words if w in _HINDI_WORDS)
        if mr > hi:
            return "mr"
        if hi > mr:
            return "hi"
        return audio_hint if audio_hint in ("hi", "mr") else "hi"
    # 4. Audio hint for Marathi or Hindi when script wasn't detected
    if audio_hint in ("mr", "hi"):
        return audio_hint
    return audio_hint if audio_hint in LANGS else detect_language(text)


async def resolve_message_language_async(text: str, audio_hint: str = None) -> str:
    """Resolve language with deep semantic understanding for Romanized speech."""
    audio_hint = (audio_hint or "").lower()[:2]
    text = (text or "").strip()
    if not text:
        return audio_hint if audio_hint in LANGS else "en"

    # 1. Script-based conclusive detection
    if _GUJARATI_RE.search(text):
        return "gu"
    if audio_hint == "gu":
        return "gu"
    if _DEVANAGARI_RE.search(text):
        return determine_message_language(text, audio_hint)
    if audio_hint in ("mr", "hi"):
        return audio_hint

    # 2. For Latin script / phonetic transliterations (e.g. Romanized Gujarati or Hindi), use LLM
    try:
        resp = await groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Identify the spoken language of the message among: gu (Gujarati), hi (Hindi), mr (Marathi), en (English). "
                        "Even if written in Latin/English alphabets, detect the spoken language. "
                        "Respond ONLY with a 2-letter code: gu, hi, mr, or en."
                    ),
                },
                {"role": "user", "content": text[:400]},
            ],
            temperature=0,
            max_tokens=10,
        )
        detected = _strip_think(resp.choices[0].message.content).strip().lower()[:2]
        if detected in LANGS:
            return detected
    except Exception as e:
        print(f"WARN resolve_message_language_async: {e}")

    return determine_message_language(text, audio_hint)



_translation_cache = {}


def _strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text or "", flags=re.DOTALL | re.IGNORECASE).strip()


async def translate_text(text: str, lang: str) -> str:
    """Translate `text` into `lang` using the LLM. Returns the original text on failure."""
    if not text or lang not in LANG_NAMES_EN:
        return text
    key = (text, lang)
    if key in _translation_cache:
        return _translation_cache[key]
    try:
        resp = await groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        f"Translate the user's text into {LANG_NAMES_EN[lang]} using its native script. "
                        "Output ONLY the translation, with no quotes or explanation."
                    ),
                },
                {"role": "user", "content": text},
            ],
            temperature=0,
            max_tokens=500,
        )
        out = _strip_think(resp.choices[0].message.content) or text
        _translation_cache[key] = out
        return out
    except Exception as e:
        print(f"ERROR translate_text: {e}")
        return text


# ---------------------------------------------------------------------------
# 8. Voice transcription (Groq Whisper first, AWS Transcribe fallback)
# ---------------------------------------------------------------------------
# Formats Groq Whisper accepts (WhatsApp voice notes are audio/ogg, opus codec).
GROQ_AUDIO_EXT = {
    "audio/ogg": "ogg",
    "audio/opus": "ogg",
    "audio/mpeg": "mp3",
    "audio/mp3": "mp3",
    "audio/mp4": "m4a",
    "audio/x-m4a": "m4a",
    "audio/wav": "wav",
    "audio/x-wav": "wav",
    "audio/webm": "webm",
    "audio/flac": "flac",
}
WHISPER_LANGS = {
    "english": "en", "en": "en",
    "hindi": "hi", "hi": "hi",
    "gujarati": "gu", "gu": "gu",
    "marathi": "mr", "mr": "mr",
}

TRANSCRIBE_FORMATS = {
    "audio/ogg": "ogg",
    "audio/opus": "ogg",
    "audio/mpeg": "mp3",
    "audio/mp3": "mp3",
    "audio/mp4": "mp4",
    "audio/aac": "mp4",
    "audio/x-m4a": "m4a",
    "audio/amr": "amr",
    "audio/wav": "wav",
    "audio/x-wav": "wav",
    "audio/webm": "webm",
    "audio/flac": "flac",
}


async def _groq_transcribe(filepath: str, ext: str, language: str = None):
    with open(filepath, "rb") as fh:
        data = fh.read()
    kwargs = dict(
        file=(f"audio.{ext}", data),
        model=WHISPER_MODEL,
        response_format="verbose_json",
        temperature=0.0,
    )
    if language:
        kwargs["language"] = language
    resp = await groq_client.audio.transcriptions.create(**kwargs)
    text = (getattr(resp, "text", "") or "").strip()
    lang_name = getattr(resp, "language", None) or (getattr(resp, "model_extra", None) or {}).get("language") or ""
    return text, str(lang_name).lower()


async def _aws_transcribe(filepath: str, content_type: str):
    bucket = os.getenv("S3_BUCKET_NAME")
    media_format = TRANSCRIBE_FORMATS.get(content_type, "ogg")
    key = f"audio/{uuid.uuid4()}.{media_format}"
    job_name = f"scam-{uuid.uuid4().hex[:12]}"

    try:
        await asyncio.to_thread(s3_client.upload_file, filepath, bucket, key)
        await asyncio.to_thread(
            transcribe_client.start_transcription_job,
            TranscriptionJobName=job_name,
            Media={"MediaFileUri": f"s3://{bucket}/{key}"},
            MediaFormat=media_format,
            IdentifyLanguage=True,
            LanguageOptions=["en-IN", "hi-IN", "gu-IN", "mr-IN"],
        )
        for _ in range(40):
            await asyncio.sleep(3)
            status = await asyncio.to_thread(
                transcribe_client.get_transcription_job, TranscriptionJobName=job_name
            )
            job = status["TranscriptionJob"]
            state = job["TranscriptionJobStatus"]
            if state == "COMPLETED":
                uri = job["Transcript"]["TranscriptFileUri"]
                async with httpx.AsyncClient(timeout=30) as client:
                    r = await client.get(uri)
                    r.raise_for_status()
                text = r.json()["results"]["transcripts"][0]["transcript"]
                return text, (job.get("LanguageCode") or "")[:2]
            if state == "FAILED":
                print(f"ERROR transcribe_audio: job failed: {job.get('FailureReason')}")
                return "", ""
        print("ERROR transcribe_audio: timed out")
        return "", ""
    except Exception as e:
        print(f"ERROR transcribe_audio: {e}")
        return "", ""
    finally:
        try:
            await asyncio.to_thread(s3_client.delete_object, Bucket=bucket, Key=key)
        except Exception:
            pass
        try:
            await asyncio.to_thread(transcribe_client.delete_transcription_job, TranscriptionJobName=job_name)
        except Exception:
            pass


async def transcribe_audio(filepath: str, content_type: str = "audio/ogg"):
    """Return (transcript, language_code). Groq Whisper takes ~1-3s, which fits Twilio's 15s webhook limit."""
    content_type = (content_type or "audio/ogg").split(";")[0].strip().lower()
    ext = GROQ_AUDIO_EXT.get(content_type)
    if ext:
        try:
            text, lang_name = await _groq_transcribe(filepath, ext)
            code = WHISPER_LANGS.get(lang_name)
            # Prioritize script if detected in transcription
            if _GUJARATI_RE.search(text):
                code = "gu"
            elif _DEVANAGARI_RE.search(text):
                words = _DEVANAGARI_WORD_RE.findall(text)
                mr = sum(1 for w in words if w in _MARATHI_WORDS)
                hi = sum(1 for w in words if w in _HINDI_WORDS)
                if mr > hi:
                    code = "mr"
                elif hi > mr:
                    code = "hi"
                elif code in ("hi", "mr"):
                    pass
                else:
                    code = "hi"
            elif text and code is None:
                # If script is completely absent and language wasn't matched, check if Hindi hint works
                text2, _ = await _groq_transcribe(filepath, ext, language="hi")
                if text2 and _DEVANAGARI_RE.search(text2):
                    text, code = text2, "hi"
            if text:
                return text, code or ""
        except Exception as e:
            print(f"WARN transcribe_audio: Groq Whisper failed ({e}), falling back to AWS Transcribe")
    return await _aws_transcribe(filepath, content_type)


# ---------------------------------------------------------------------------
# 9. LLM classifier
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a scam and fraud detection engine. The message may be in English, Hindi, Gujarati or Marathi (native script or romanized). Analyze it and respond ONLY with a JSON object, no other text:
{"verdict": "SCAM" or "CLEAN" or "SUSPICIOUS", "confidence": 0.0 to 1.0, "reason": "one sentence explanation", "language": "en" or "hi" or "gu" or "mr"}

"language" is the language the sender wrote in. Write "reason" in that SAME language and script (English for en, Devanagari for Hindi and Marathi, Gujarati script for Gujarati).

Common scam patterns: prize/lottery claims, urgent payment requests, OTP phishing, bank/government impersonation, APK download links, job offers requiring upfront payment, crypto investment schemes, fake emergency money requests."""


def parse_llm_json(content: str) -> dict:
    text = (content or "").strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)
    return json.loads(text)


async def classify_with_llm(text: str, target_lang: str = None) -> dict:
    if not text or not text.strip():
        return {"verdict": "UNKNOWN", "confidence": 0.0, "reason": "No text provided to analyze"}

    lang_instruction = ""
    if target_lang and target_lang in LANG_NAMES_EN:
        lang_instruction = (
            f"\nIMPORTANT: The user message was spoken/written in {LANG_NAMES_EN[target_lang]} (code '{target_lang}'). "
            f"You MUST set 'language': '{target_lang}' and write the 'reason' exclusively in {LANG_NAMES_EN[target_lang]} using native script."
        )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + lang_instruction},
        {"role": "user", "content": text[:6000]},
    ]
    try:
        try:
            response = await groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=500,  # Indic scripts use many tokens per word
            )
        except Exception as e:
            print(f"WARN classify_with_llm: json mode failed ({e}), retrying without it")
            response = await groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=messages,
                temperature=0.1,
                max_tokens=800,
            )
        parsed = parse_llm_json(response.choices[0].message.content)
        detected = str(parsed.get("language", "")).strip().lower()[:2]
        lang = target_lang or (detected if detected in LANGS else "")
        parsed["language"] = lang
        parsed["reason_lang"] = lang or "en"
        return parsed
    except Exception as e:
        print(f"ERROR classify_with_llm: {e}")
        return {"verdict": "UNKNOWN", "confidence": 0.0, "reason": "LLM error"}


# ---------------------------------------------------------------------------
# 10. Financial & Fraud Detection
# ---------------------------------------------------------------------------
FINANCIAL_PATTERNS = re.compile(
    r"(\b(money|cash|fund|funds|payment|pay|transfer|wire|deposit|withdraw|"
    r"bank|account|credit|debit|card|loan|fee|charge|bill|invoice|"
    r"upi|gpay|paytm|phonepe|paypal|wallet|crypto|bitcoin|btc|usdt|"
    r"prize|lottery|winner|reward|cashback|refund|salary|income|earn|"
    r"investment|profit|roi|bonus|cheque|rupees|rs|inr|usd|dollars|eur|"
    r"kyc|otp|cvv|pin|password|passcode|paise|paisa|khata|khate|bhejo|pathva|moklo)\b|[₹$€£]\s*\d+)",
    re.IGNORECASE
)

# Hindi / Marathi (Devanagari) and Gujarati money words. Matched as substrings
# because \b does not work reliably with combining vowel signs.
FINANCIAL_PATTERNS_INDIC = re.compile(
    "|".join([
        # Hindi / Marathi
        "पैसे", "पैसा", "पैशां", "रुपये", "रुपए", "रूपये", "रुपया", "बैंक", "बँक", "खाता", "खाते", "खात्या",
        "अकाउंट", "ओटीपी", "पिन", "पासवर्ड", "सीवीवी", "ट्रांसफर", "ट्रान्सफर", "भुगतान", "लोन", "कर्ज",
        "निवेश", "गुंतवणूक", "इनाम", "बक्षीस", "लॉटरी", "पेमेंट", "यूपीआई", "केवाईसी", "रकम", "रक्कम",
        "ब्याज", "व्याज", "उधार", "क्रेडिट", "डेबिट", "भेजो", "पाठवा",
        # Gujarati
        "પૈસા", "રૂપિયા", "બેંક", "બેન્ક", "ખાતું", "ખાતા", "ખાતામાં", "એકાઉન્ટ", "ઓટીપી", "પિન", "પાસવર્ડ",
        "સીવીવી", "ટ્રાન્સફર", "ચુકવણી", "મોકલો", "મોકલી", "જમા", "ઉપાડ", "લોન", "રોકાણ", "ઇનામ",
        "લોટરી", "પેમેન્ટ", "કેવાયસી", "રકમ", "વ્યાજ", "ઉધાર",
    ])
)


def is_financial_or_fraud(text: str, verdict: dict) -> bool:
    v = str(verdict.get("verdict", "")).upper()
    if v in ("SCAM", "SUSPICIOUS"):
        return True
    if text and (FINANCIAL_PATTERNS.search(text) or FINANCIAL_PATTERNS_INDIC.search(text)):
        return True
    return False


# ---------------------------------------------------------------------------
# 11. Trusted contacts (registration, verification, lookup)
# ---------------------------------------------------------------------------
# Each user can register ONE trusted contact. The contact must prove they agree
# (and that their WhatsApp is reachable) by sending "ACCEPT <code>" to the bot.
# TRUSTED_CONTACT_NUMBER in .env is the pre-verified default for everyone.
CONTACTS_FILE = os.path.join(BASE_DIR, "trusted_contacts.json")


def _load_contacts() -> dict:
    try:
        with open(CONTACTS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_contacts(data: dict) -> None:
    with open(CONTACTS_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def to_wa_number(raw: str):
    """Normalize '+91 98765-43210' / 'whatsapp:+9198...' to 'whatsapp:+9198...'; None if invalid."""
    cleaned = re.sub(r"[\s\-()]", "", (raw or "").replace("whatsapp:", ""))
    return f"whatsapp:{cleaned}" if re.fullmatch(r"\+\d{8,15}", cleaned) else None


def get_trusted_contact(user: str) -> str:
    """Verified contact registered by `user`, else the .env default, else ''."""
    entry = _load_contacts().get(user)
    if entry and entry.get("verified") and entry.get("contact"):
        return entry["contact"]
    return to_wa_number(os.getenv("TRUSTED_CONTACT_NUMBER", "")) or ""


def handle_command(text: str, sender: str):
    """
    Handle bot commands. Returns (reply_or_None, notifications) where notifications
    is a list of (to_number, body) to push via the Twilio REST API.
    """
    t = (text or "").strip()
    low = t.lower()
    bot_number = os.getenv("TWILIO_WHATSAPP_NUMBER", "").replace("whatsapp:", "")

    # The trusted contact confirms with: ACCEPT 123456
    m = re.fullmatch(r"accept\s+(\d{6})", low)
    if m:
        contacts = _load_contacts()
        for user, entry in contacts.items():
            if entry.get("contact") == sender and not entry.get("verified") and entry.get("code") == m.group(1):
                entry["verified"] = True
                entry.pop("code", None)
                _save_contacts(contacts)
                who = user.replace("whatsapp:", "")
                return (
                    f"✅ Thank you! You are now the trusted contact of {who}. "
                    "You will receive an alert here whenever they receive a suspicious or money-related message.",
                    [(user, f"✅ {sender.replace('whatsapp:', '')} accepted and is now your verified trusted contact.")],
                )
        return ("❌ That code is invalid or has already been used.", [])

    cmd_match = re.match(r"^/(trust|emergency|contact)(\s+.*)?$", low)
    if cmd_match:
        arg = (cmd_match.group(2) or "").strip()
        arg_l = arg.lower()
        contacts = _load_contacts()
        entry = contacts.get(sender)

        if arg_l in ("", "help"):
            return (
                "🛡️ *Emergency / Trusted Contact Setup*\n"
                "• /emergency +91XXXXXXXXXX — register an emergency contact\n"
                "• /emergency status — check current emergency contact\n"
                "• /emergency remove — remove emergency contact\n\n"
                "When any bank account, OTP, payment, or scam request is detected, an instant emergency warning is dispatched to this contact.",
                [],
            )

        if arg_l == "status":
            if entry:
                state = "✅ verified" if entry.get("verified") else "⏳ waiting for them to accept"
                return (f"Your emergency contact: {entry['contact'].replace('whatsapp:', '')} ({state})", [])
            default = os.getenv("TRUSTED_CONTACT_NUMBER", "").strip()
            if default:
                return (f"Using the default emergency contact: {default.replace('whatsapp:', '')}", [])
            return ("You have no emergency contact configured. Send: /emergency +91XXXXXXXXXX", [])

        if arg_l == "remove":
            if entry:
                contacts.pop(sender, None)
                _save_contacts(contacts)
                return ("🗑️ Your emergency contact was removed.", [])
            return ("You have no registered emergency contact.", [])

        number = to_wa_number(arg)
        if not number:
            return ("❌ Please send the number with country code, e.g. /emergency +919876543210", [])
        if number == sender:
            return ("❌ Your emergency contact must be someone else.", [])

        code = f"{secrets.randbelow(10**6):06d}"
        contacts[sender] = {"contact": number, "verified": False, "code": code}
        _save_contacts(contacts)
        return (
            f"📨 Almost done! Ask your emergency contact {number.replace('whatsapp:', '')} to:\n"
            f"1️⃣ Send \"{SANDBOX_JOIN_PHRASE}\" to +{bot_number.lstrip('+')} on WhatsApp (one-time opt-in)\n"
            f"2️⃣ Then send: ACCEPT {code}\n\n"
            "Once they accept, emergency alerts with full context and transcripts will be forwarded to them.",
            [],
        )

    return (None, [])


# ---------------------------------------------------------------------------
# 12. Twilio helpers, alerts and reply formatting
# ---------------------------------------------------------------------------
ICONS = {"SCAM": "SCAM ❌", "CLEAN": "CLEAN ✅", "SUSPICIOUS": "SUSPICIOUS ⚠️"}


def build_twiml_reply(body: str = "") -> Response:
    resp = MessagingResponse()
    if body:
        resp.message(body)
    return Response(content=str(resp), media_type="application/xml")


async def send_whatsapp(to: str, from_: str, body: str) -> bool:
    try:
        await asyncio.to_thread(twilio_client.messages.create, to=to, from_=from_, body=body[:1600])
        return True
    except Exception as e:
        err_msg = str(e)
        if "ContentSid Required" in err_msg or "21654" in err_msg or "63016" in err_msg:
            print("INFO: Twilio requires an approved ContentSid template to message a number outside an active 24h session.")
        elif "verified recipient" in err_msg or "63015" in err_msg or "21608" in err_msg:
            print(f"ERROR send_whatsapp: {to} has not joined the Twilio WhatsApp sandbox. "
                  f"They must send '{SANDBOX_JOIN_PHRASE}' to {from_} first.")
        else:
            print(f"ERROR send_whatsapp: {e}")
        return False


def normalize_result(result: dict) -> dict:
    result = result if isinstance(result, dict) else {}
    verdict = str(result.get("verdict", "UNKNOWN")).strip().upper()
    if verdict not in ICONS:
        verdict = "UNKNOWN"
    try:
        conf = float(result.get("confidence", 0))
    except (TypeError, ValueError):
        conf = 0.0
    if conf > 1:
        conf /= 100
    conf = max(0.0, min(conf, 1.0))
    reason = str(result.get("reason") or "N/A")[:500]
    reason_lang = str(result.get("reason_lang") or "en")
    return {
        "verdict": verdict,
        "confidence": conf,
        "reason": reason,
        "reason_lang": reason_lang if reason_lang in LANGS else "en",
        "transcript": str(result.get("transcript") or ""),
    }


async def localize_result(result: dict, lang: str) -> dict:
    """Return a normalized result whose reason is written strictly in `lang`."""
    r = normalize_result(result)
    reason = r["reason"]
    needs_translation = False

    if reason and reason != "N/A":
        if lang == "gu" and not _GUJARATI_RE.search(reason):
            needs_translation = True
        elif lang in ("hi", "mr") and not _DEVANAGARI_RE.search(reason):
            needs_translation = True
        elif lang == "mr":
            words = _DEVANAGARI_WORD_RE.findall(reason)
            if any(w in _HINDI_WORDS for w in words):
                needs_translation = True
        elif lang == "en" and (_GUJARATI_RE.search(reason) or _DEVANAGARI_RE.search(reason)):
            needs_translation = True
        elif r.get("reason_lang") != lang:
            needs_translation = True

    if needs_translation and reason and reason != "N/A":
        r["reason"] = await translate_text(reason, lang)
        r["reason_lang"] = lang
    return r


def format_reply(result: dict, lang: str = "en", is_financial: bool = False) -> str:
    s = STRINGS.get(lang, STRINGS["en"])
    r = normalize_result(result)
    verdict = r["verdict"]
    conf = int(round(r["confidence"] * 100))
    lines = [s["title"], ""]
    if r["transcript"]:
        lines += [f"{s['heard']}: \"{r['transcript'][:300]}\"", ""]
    lines += [
        f"{s['verdict']}: {s['verdicts'].get(verdict, s['verdicts']['UNKNOWN'])}",
        f"{s['confidence']}: {conf}%",
        f"{s['reason']}: {r['reason']}",
    ]
    msg = "\n".join(lines)
    if is_financial:
        msg += "\n\n" + s["fin_alert"]
    return msg


async def build_reply(verdict: dict, analyzed_text: str, is_fin: bool, forced_lang: str = None) -> str:
    """Detect the user's language and return the final localized reply text strictly in that language."""
    lang = forced_lang or (verdict.get("language") if isinstance(verdict, dict) else None)
    if not lang or lang not in LANGS:
        lang = determine_message_language(analyzed_text)
    localized = await localize_result(verdict, lang)
    return format_reply(localized, lang, is_fin)


async def send_trusted_alert(sender: str, message_text: str, verdict: dict, twilio_from: str) -> None:
    trusted_number = get_trusted_contact(sender)
    if not trusted_number:
        print("INFO: no trusted contact configured, skipping alert")
        return

    norm = normalize_result(verdict)
    v_icon = ICONS.get(norm["verdict"], norm["verdict"])
    conf = int(round(norm["confidence"] * 100))
    snippet = (message_text or "No text content").strip()
    if len(snippet) > 400:
        snippet = snippet[:400] + "..."

    alert_body = (
        "🚨 *FRAUD & FINANCIAL ALERT* 🚨\n\n"
        "A message containing financial mentions or suspected fraud was detected.\n\n"
        f"👤 *Sender:* {sender or 'Unknown'}\n"
        f"🏷️ *Verdict:* {v_icon} ({conf}%)\n"
        f"💡 *Reason:* {norm['reason']}\n\n"
        f"💬 *Detected Content:*\n\"{snippet}\""
    )
    print(f"Dispatching trusted contact alert to {trusted_number}...")
    await send_whatsapp(to=trusted_number, from_=twilio_from, body=alert_body)


async def send_notifications(notifications, twilio_from: str) -> None:
    for to, body in notifications:
        await send_whatsapp(to, twilio_from, body)


# ---------------------------------------------------------------------------
# 13. Media analysis pipeline
# ---------------------------------------------------------------------------
async def analyze_media(body: str, media_url: str, content_type: str) -> tuple[dict, str]:
    """
    Download and inspect an attachment.
    Returns: (verdict_dict, full_analyzed_text)
    """
    content_type = (content_type or "").lower()
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = await download_media(media_url, tmpdir, content_type)
        filename = os.path.basename(filepath).lower()

        # 1. Voice Notes (any of English / Hindi / Gujarati / Marathi)
        if content_type.startswith("audio/"):
            transcript, spoken_lang = await transcribe_audio(filepath, content_type)
            if not transcript.strip():
                fallback_lang = spoken_lang if spoken_lang in LANGS else determine_message_language(body)
                return ({
                    "verdict": "UNKNOWN",
                    "confidence": 0.0,
                    "reason": STRINGS.get(fallback_lang, STRINGS["en"])["failed"],
                    "language": fallback_lang,
                    "reason_lang": fallback_lang,
                }, body)
            target_lang = await resolve_message_language_async(transcript, spoken_lang)
            combined = f"{body}\n{transcript}".strip()
            verdict = rule_verdict(combined) or await classify_with_llm(combined, target_lang=target_lang)
            verdict["language"] = target_lang
            verdict["transcript"] = transcript
            if "reason_lang" not in verdict:
                verdict["reason_lang"] = "en"
            return (verdict, combined)

        # 2. Images (OCR text extraction)
        if content_type.startswith("image/"):
            ocr_text = await extract_image_text(filepath)
            combined = f"{body}\n{ocr_text}".strip()
            if ocr_text:
                verdict = rule_verdict(combined) or await classify_with_llm(combined)
                return (verdict, combined)
            if body.strip():
                verdict = rule_verdict(body) or await classify_with_llm(body)
                return (verdict, body)
            vt = None
            try:
                vt = await scan_file_virustotal(filepath)
            except Exception as e:
                print(f"ERROR scan_file_virustotal on image: {e}")
            if vt and vt["malicious"] > 0:
                return ({
                    "verdict": "SCAM",
                    "confidence": 0.99,
                    "reason": f"VirusTotal: {vt['malicious']} of {vt['total']} engines flagged this image file as malicious"
                }, "")
            return ({"verdict": "CLEAN", "confidence": 0.85, "reason": "Image scanned; no suspicious text or malicious payloads found"}, "")

        # 3. APK Files (Scan through VirusTotal API + APK Manifest check)
        if is_apk(filepath, content_type) or filename.endswith(".apk"):
            vt = None
            try:
                vt = await scan_file_virustotal(filepath)
            except Exception as e:
                print(f"ERROR scan_file_virustotal on APK: {e}")

            if vt and vt["malicious"] > 0:
                reason = f"VirusTotal: {vt['malicious']} of {vt['total']} engines flagged this APK as malicious"
                conf = 0.99
            else:
                reason = "APK file attachment detected — automatic scam flag (unverified app sideloading)"
                conf = 1.0
            return ({"verdict": "SCAM", "confidence": conf, "reason": reason}, body)

        # 4. PDF Files (Scan through VirusTotal API + Extract text)
        if content_type == "application/pdf" or filename.endswith(".pdf"):
            pdf_text = await extract_pdf_text(filepath)
            combined = f"{body}\n{pdf_text}".strip()

            vt = None
            try:
                vt = await scan_file_virustotal(filepath)
            except Exception as e:
                print(f"ERROR scan_file_virustotal on PDF: {e}")

            if vt and vt["malicious"] > 0:
                return ({
                    "verdict": "SCAM",
                    "confidence": 0.99,
                    "reason": f"VirusTotal: {vt['malicious']} of {vt['total']} engines flagged this PDF as malicious"
                }, combined)

            if combined:
                text_verdict = rule_verdict(combined) or await classify_with_llm(combined)
                if text_verdict.get("verdict") == "SCAM":
                    return (text_verdict, combined)
                if vt and vt.get("suspicious", 0) > 0:
                    return ({
                        "verdict": "SUSPICIOUS",
                        "confidence": 0.75,
                        "reason": f"VirusTotal marked this PDF suspicious ({vt['suspicious']} engines), combined with text review."
                    }, combined)
                return (text_verdict, combined)

            if vt is None:
                return ({"verdict": "UNKNOWN", "confidence": 0.0, "reason": "File scan unavailable, please try again later"}, "")
            if vt.get("suspicious", 0) > 0:
                return ({"verdict": "SUSPICIOUS", "confidence": 0.7, "reason": f"VirusTotal marked this PDF suspicious ({vt['suspicious']} engines)"}, "")
            return ({"verdict": "CLEAN", "confidence": 0.9, "reason": f"VirusTotal: 0 of {vt.get('total', 0)} engines flagged this PDF"}, "")

        # 5. General Attachments
        vt = None
        try:
            vt = await scan_file_virustotal(filepath)
        except Exception as e:
            print(f"ERROR scan_file_virustotal: {e}")

        if vt and vt["malicious"] > 0:
            return ({
                "verdict": "SCAM",
                "confidence": 0.99,
                "reason": f"VirusTotal: {vt['malicious']} of {vt['total']} engines flagged this attachment as malicious"
            }, body)

        if body.strip():
            verdict = rule_verdict(body) or await classify_with_llm(body)
            return (verdict, body)

        if vt and vt.get("suspicious", 0) > 0:
            return ({"verdict": "SUSPICIOUS", "confidence": 0.65, "reason": f"VirusTotal: {vt['suspicious']} engines flagged this file as suspicious"}, "")
        return ({"verdict": "CLEAN", "confidence": 0.8, "reason": "Attachment scanned clean via VirusTotal"}, "")


# ---------------------------------------------------------------------------
# 14. Main Webhook Endpoint
# ---------------------------------------------------------------------------
MEDIA_REPLY_TIMEOUT = 11  # seconds; Twilio drops webhooks after 15s
_bg_tasks: set = set()


async def process_media(text: str, sender: str, from_number: str, url: str, ctype: str) -> str:
    """Analyze an attachment and return the localized reply. Never raises."""
    try:
        verdict, analyzed_text = await analyze_media(text, url, ctype)
        forced_lang = verdict.get("language")
        is_fin = is_financial_or_fraud(analyzed_text, verdict)
        if is_fin:
            alert = asyncio.create_task(send_trusted_alert(sender, analyzed_text, verdict, from_number))
            _bg_tasks.add(alert)
            alert.add_done_callback(_bg_tasks.discard)
            return await build_reply(verdict, analyzed_text, True, forced_lang=forced_lang)
        return await build_reply(verdict, analyzed_text, False, forced_lang=forced_lang)
    except Exception as e:
        print(f"ERROR media processing: {e}")
        return STRINGS[determine_message_language(text)]["failed"]


@app.post("/webhook")
async def webhook(
    background_tasks: BackgroundTasks,
    Body: str = Form(""),
    From: str = Form(""),
    To: str = Form(""),
    NumMedia: int = Form(0),
    MediaUrl0: str = Form(""),
    MediaContentType0: str = Form(""),
):
    from_number = To or os.getenv("TWILIO_WHATSAPP_NUMBER", "")
    text = Body or ""
    try:
        # Step 0: bot commands (/emergency, /trust, ACCEPT <code>) — never run through detection
        if NumMedia == 0:
            command_reply, notifications = handle_command(text, From)
            if command_reply is not None:
                if notifications:
                    background_tasks.add_task(send_notifications, notifications, from_number)
                return build_twiml_reply(command_reply)

        # Step 1: rule engine (instant) — only for plain text; media is always analyzed
        verdict = rule_verdict(text) if not (NumMedia >= 1 and MediaUrl0) else None
        if verdict:
            is_fin = is_financial_or_fraud(text, verdict)
            if is_fin:
                background_tasks.add_task(send_trusted_alert, From, text, verdict, from_number)
            text_lang = determine_message_language(text)
            return build_twiml_reply(await build_reply(verdict, text, is_fin, forced_lang=text_lang))

        # Step 2: media processing (voice notes, images, PDFs, APKs)
        if NumMedia >= 1 and MediaUrl0:
            task = asyncio.create_task(
                process_media(text, From, from_number, MediaUrl0, MediaContentType0)
            )
            _bg_tasks.add(task)
            task.add_done_callback(_bg_tasks.discard)
            done, _ = await asyncio.wait({task}, timeout=MEDIA_REPLY_TIMEOUT)
            if done:
                return build_twiml_reply(task.result())
            # Too slow for Twilio's 15s webhook limit: ack now, push the result later via REST.
            async def _late_reply():
                await send_whatsapp(From, from_number, await task)
            late = asyncio.create_task(_late_reply())
            _bg_tasks.add(late)
            late.add_done_callback(_bg_tasks.discard)
            return build_twiml_reply(STRINGS[determine_message_language(text)]["working"])

        # Step 3: text-only LLM fallback
        detected_lang = await resolve_message_language_async(text)
        verdict = await classify_with_llm(text, target_lang=detected_lang)
        is_fin = is_financial_or_fraud(text, verdict)
        if is_fin:
            background_tasks.add_task(send_trusted_alert, From, text, verdict, from_number)
        return build_twiml_reply(await build_reply(verdict, text, is_fin, forced_lang=detected_lang))
    except Exception as e:
        print(f"ERROR: {e}")
        return build_twiml_reply(STRINGS[determine_message_language(text)]["failed"])


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "missing_env": _missing,
        "model": GROQ_MODEL,
        "whisper_model": WHISPER_MODEL,
        "languages": list(LANGS),
        "default_trusted_contact_configured": bool(os.getenv("TRUSTED_CONTACT_NUMBER", "").strip()),
    }


# ---------------------------------------------------------------------------
# 15. App startup
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
