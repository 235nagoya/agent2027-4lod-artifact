import os
import re
from openai import OpenAI

client = OpenAI()

test_prompt = "Pythonで『Hello World』を出力するだけの単純なコードを書いてください。"

print("OpenAI APIへ接続テスト中...")

try:
    response = client.chat.completions.create(
        model="gpt-5.5",
        messages=[{"role": "user", "content": test_prompt}]
    )
    print("\n[成功] API応答を受信しました！チャージ残高・接続ともに問題ありません。")
    print("AIからの返答概要:", response.choices[0].message.content[:50], "...")

except Exception as e:
    print(f"\n[エラーが発生しました]: {e}")
