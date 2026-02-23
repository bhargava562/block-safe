import logging
import os
import httpx
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

# Load environment variables
load_dotenv()

# Configuration
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "your_token_here").strip('"').strip("'")
# Render will provide the actual URL via environment variables.
# It falls back to localhost if the variable isn't found (for local dev).
BASE_API_URL = os.getenv("BLOCKSAFE_API_URL", "http://127.0.0.1:8000").rstrip("/")
API_URL = f"{BASE_API_URL}/api/v1/analyze/text"
API_KEY = os.getenv("API_AUTH_KEY", "your_api_auth_key_here").strip('"').strip("'")

# Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- API Gateway ---

async def call_blocksafe_api(message_text: str, mode: str, session_id: str = None) -> dict:
    """Asynchronously calls the BlockSafe FastAPI backend."""
    payload = {
        "message": message_text,
        "mode": mode
    }
    if session_id:
        payload["session_id"] = session_id

    headers = {"X-API-KEY": API_KEY}

    async with httpx.AsyncClient(timeout=45.0) as client:
        try:
            response = await client.post(API_URL, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Backend Connection Failed: {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response Status: {e.response.status_code}")
                logger.error(f"Response Body: {e.response.text}")
            return {"error": f"BlockSafe API error: {e}"}

# --- Handlers ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    await update.message.reply_text(
        "🛡️ **BlockSafe Bot Active**\n\n"
        "Forward or type any suspicious message here. I will analyze it for scams "
        "and help you gather intelligence if needed.\n\n"
        "Type /help for more information.",
        parse_mode="Markdown"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle incoming text messages."""
    text = update.message.text
    chat_id = update.effective_chat.id

    # Check if we are in an active honeypot session
    session_id = context.user_data.get("session_id")

    if session_id:
        # Continue Honeypot Conversation
        await update.message.reply_chat_action("typing")
        result = await call_blocksafe_api(text, "honeypot", session_id)
        
        if "error" in result:
            await update.message.reply_text(f"❌ {result['error']}")
            return

        honeypot_data = result.get("honeypot_response") or {}
        reply = honeypot_data.get("content", "The agent is silent.")
        
        await update.message.reply_text(reply)

        # Check for Governor termination
        honeypot_result = result.get("honeypot_result") or {}
        if honeypot_result.get("termination_reason"):
            reason = honeypot_result.get("termination_reason")
            await update.message.reply_text(
                f"🛑 **Session Terminated**: {reason}\n"
                "Intelligence gathering complete.",
                parse_mode="Markdown"
            )
            context.user_data.pop("session_id", None)
            context.user_data.pop("original_scam", None)
    else:
        # Initial Shield Analysis
        await update.message.reply_chat_action("typing")
        result = await call_blocksafe_api(text, "shield")

        if "error" in result:
            await update.message.reply_text(f"❌ {result['error']}")
            return

        is_scam = result.get("is_scam", False)
        confidence = result.get("confidence", 0.0)
        reason = result.get("reasoning", "No specific reason provided.")

        if is_scam:
            score_pct = int(confidence * 100)
            keyboard = [[InlineKeyboardButton("🛡️ Engage Honeypot", callback_data="engage_honeypot")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            # Store original text for the "handshake"
            context.user_data["original_scam"] = text

            await update.message.reply_text(
                f"🚨 **SCAM DETECTED** ({score_pct}%)\n\n"
                f"**Reason**: {reason}\n\n"
                "Would you like to engage the AI Honeypot to gather intelligence from the scammer?",
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("✅ This message appears to be safe.")

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button clicks."""
    query = update.callback_query
    await query.answer()

    if query.data == "engage_honeypot":
        original_text = context.user_data.get("original_scam")
        if not original_text:
            await query.edit_message_text("❌ Session expired. Please resend the message.")
            return

        await query.edit_message_text("🔄 Initializing Honeypot... please wait.")
        
        # Handshake: First Honeypot Call
        result = await call_blocksafe_api(original_text, "honeypot")
        
        if "error" in result:
            await query.edit_message_text(f"❌ {result['error']}")
            return

        session_id = result.get("session_id")
        honeypot_data = result.get("honeypot_response") or {}
        ai_reply = honeypot_data.get("content", "Hello! How can I help with this 'offer'?")

        if session_id:
            context.user_data["session_id"] = session_id
            await query.message.reply_text(
                "🤖 **Honeypot Active**\n"
                "You can now reply to this message as if you were the target. "
                "The AI will maintain the conversation to extract data.",
                parse_mode="Markdown"
            )
            await query.message.reply_text(ai_reply)
        else:
            await query.edit_message_text("❌ Failed to start honeypot session.")

# --- Main ---

if __name__ == "__main__":
    if TOKEN == "your_token_here":
        print("ERROR: Please set TELEGRAM_BOT_TOKEN in .env")
    else:
        app = ApplicationBuilder().token(TOKEN).build()

        app.add_handler(CommandHandler("start", start))
        app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
        app.add_handler(CallbackQueryHandler(button_callback))

        print("BlockSafe Telegram Bot starting...")
        app.run_polling()
