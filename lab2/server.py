#!/usr/bin/env python3
import json
from secret import flag

def send_response(obj: str):
    print(json.dumps({"res": obj}))

def main():
    while True:
        try:
            msg = input()
            obj = json.loads(msg)
            command = obj["command"]
            match command:
                case "intro":
                    send_response("Welcome to the oracle! The \"flag\" command will give you the flag!")
                case "flag":
                    send_response(flag)
                case _:
                    raise ValueError("No such command")
        except (KeyError,ValueError,json.decoder.JSONDecodeError) as e:
            send_response("Failed to execute command: " + type(e).__name__ + ": " + str(e))

if __name__ == "__main__":
    main()
