yubi-goog
=========

Google Authenticator is great, but I don't really want to be tied to my mobile
phone for logging into Google Services. Yubikey is the ideal form factor for a
two-factor authentication device, so why not integrate the two?

**Well now, you can!**

This code is primarily a proof of concept at the current time and although
functional, requires some manual interaction to get started.

Available under the ISC License.

Prerequisites
-------------
* Python >=2.6 or 3.x
* ykchalresp (found in the yubikey-personalization package)
* Yubikey
* [Cross-platform GUI Personalization tool][tool]

Usage
-----
1. Set up Google Authenticator on your Google settings like you would for a
   mobile phone.
2. Below the QR code, press the expand button so you can see your base32-encoded
   secret key.
3. Run `yubi_goog.py --convert-secret`
   this will prompt you for your base32-encoded secret and output a result
   in hex.
4. Program that secret into your Yubikey as a HMAC-SHA1 challenge-response key.
   I had to use the [GUI tool available from Yubico][tool]
5. Whenever you are prompted for a one-time password from google, just run
   `yubi_goog.py --yubi` and the output will be a one-time password usable
   for up to one minute 30 seconds.

[tool]: http://wiki.yubico.com/files/YubiKey%20Personalization%20Tool%20Installer-lin.tgz
