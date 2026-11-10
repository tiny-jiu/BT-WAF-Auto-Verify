# BT-WAF Auto Verify

Automatic detection and protocol handling for five BT-WAF plugin challenge modes. This version is intended for the plugin, not the cloud service.

## Supported modes

| Mode | How it is handled |
| --- | --- |
| Slider | Finds the challenge script, extracts its values, and calculates the request |
| Human check | Reads the embedded values and submits the calculated response |
| Browser check | Builds the fingerprint and transformed value required by the endpoint |
| Image code | Matches the downloaded image against the local image library |
| JavaScript redirect | Follows the `btwaf` redirect parameter |

## Image library

The `captcha/` directory contains 400 pre-generated PNG images. The script compares pixels against the downloaded image and reads the answer from the matching filename.

## Usage

```bash
pip install requests pillow
python auto_verify.py http://target.example/
```

For security research and authorized testing only.
