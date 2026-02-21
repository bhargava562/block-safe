import os
import asyncio
from telegram import Bot
from dotenv import load_dotenv

load_dotenv()

async def check_telegram_connectivity():
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token or token == "your_token_here":
        print("❌ TELEGRAM_BOT_TOKEN is not set in .env")
        return

    bot = Bot(token=token)
    try:
        me = await bot.get_me()
        print(f"✅ Telegram Connectivity Verified!")
        print(f"   Bot Username: @{me.username}")
        print(f"   Bot ID: {me.id}")
    except Exception as e:
        print(f"❌ Telegram API Error: {e}")

if __name__ == "__main__":
    asyncio.run(check_telegram_connectivity())
