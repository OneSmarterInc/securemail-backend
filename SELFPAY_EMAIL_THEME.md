# MySelfPay email branding

All notifications whose authorized integration source is `selfpay` use the
MySelfPay red-and-neutral HTML template: booking invitations, portal OTPs and
other portal notifications. The SMTP worker determines the source from scoped
thread/challenge records, not subject text, recipient domains or a branding hint.
Other integrations and ordinary Secure Mail notifications keep their existing
theme. Ordinary staff email is unchanged.

The HTML uses table layout, inline core styles, a responsive maximum width and
system fonts. It needs no remote images, fonts, scripts or tracking pixels.
Dynamic content remains escaped and links retain the existing URL checks. OTPs
appear once in the HTML, with their current ten-minute expiry. The text alternative
is preserved; the old queued booking signature is normalized to Patient Care /
MySelfPay at delivery. Already-delivered emails cannot be changed or recalled.

This is a Secure Mail backend deployment. No migration, environment change or
key-service restart is required. Restart the API, outbox worker and scheduler
after selecting the new release. Do not resend old messages merely to update
their appearance. Clinic-only delivery, SMTP credentials, OTP verification and
the SelfPay approval workflow are unchanged.

Validation: 45 focused email/SMTP/portal tests passed; the full synthetic backend
suite passed with 625 passed and 19 skipped. Ruff lint and formatting checks passed.
Synthetic OTP, booking and
update templates rendered at 360px and 1440px without horizontal overflow, with
visual inspection. Browser previews are not a Gmail/Outlook compatibility test;
no actual email was sent during validation.
