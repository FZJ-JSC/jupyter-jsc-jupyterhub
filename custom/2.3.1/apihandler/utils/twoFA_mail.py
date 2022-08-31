import smtplib

from M2Crypto import BIO
from M2Crypto import SMIME
from M2Crypto import X509

COMMASPACE = ", "

ssl_key = None
ssl_cert = None


def sendsmime(
    from_addr,
    to_addrs,
    subject,
    msg,
    from_key,
    from_cert=None,
    to_certs=None,
    smtpd="localhost",
):
    msg_bio = BIO.MemoryBuffer(msg)
    sign = from_key
    encrypt = to_certs

    s = SMIME.SMIME()
    if sign:
        s.load_key(from_key, from_cert)
        p7 = s.sign(msg_bio, flags=SMIME.PKCS7_TEXT)
        msg_bio = BIO.MemoryBuffer(msg)  # Recreate coz sign() has consumed it.

    if encrypt:
        sk = X509.X509_Stack()
        for x in to_certs:
            sk.push(X509.load_cert(x))
        s.set_x509_stack(sk)
        s.set_cipher(SMIME.Cipher("des_ede3_cbc"))
        tmp_bio = BIO.MemoryBuffer()
        if sign:
            s.write(tmp_bio, p7)
        else:
            tmp_bio.write(msg)
        p7 = s.encrypt(tmp_bio)

    out = BIO.MemoryBuffer()
    out.write("From: %s\r\n" % from_addr)
    out.write("To: %s\r\n" % ", ".join(to_addrs))
    out.write("Subject: %s\r\n" % subject)
    if encrypt:
        s.write(out, p7)
    else:
        if sign:
            s.write(out, p7, msg_bio, SMIME.PKCS7_TEXT)
        else:
            out.write("\r\n")
            out.write(msg)
    out.close()

    smtp = smtplib.SMTP()
    smtp.connect(smtpd)
    smtp.sendmail(from_addr, to_addrs, out.read())
    smtp.quit()


def send_mail(to, subject, text):
    sender = "jupyter.jsc@fz-juelich.de"
    server = "mail.fz-juelich.de"
    sendsmime(
        sender,
        to,
        subject,
        str.encode(text),
        ssl_key,
        ssl_cert,
        to_certs=None,
        smtpd=server,
    )


def send_user_mail(receiver, code, unit, value, url):
    if type(receiver) == list:
        to = receiver
    elif type(receiver) == str:
        to = [receiver]
    else:
        raise Exception("Type {} for receiver not supported".format(type(receiver)))
    subject = "Request - 2FA for Jupyter-JSC"
    text = """\
Dear Jupyter-JSC user,

you have requested to enable 2-factor authentication for your Jupyter-JSC account via the 2FA webpage {url}2FA.
This is the corresponding confirmation email with the necessary activation link.

To enable 2-factor authentication for your Jupyter-JSC account, please open the following activation link:
{url}2FA/{code}
This activation link is valid for the next {value} {unit}.

If you do not want to enable 2-factor authentication for Jupyter-JSC, you can simply ignore this email.
More details on 2-factor authentication for Jupyter-JSC accounts can be found at {url}2FA/details.

If you have not requested 2-factor authentication for your Jupyter-JSC account, please reply to this false confirmation email and let us know.

Best regards
Your Jupyter-JSC Team
    """.format(
        code=code, value=value, unit=unit, url=url
    )
    send_mail(to, subject, text)


def send_user_mail_delete(receiver):
    if type(receiver) == list:
        to = receiver
    elif type(receiver) == str:
        to = [receiver]
    else:
        raise Exception("Type {} for receiver not supported".format(type(receiver)))
    subject = "Removal - 2FA for Jupyter-JSC"
    text = """\
Dear Jupyter-JSC user,

you have requested to remove 2-factor authentication for your Jupyter-JSC account via the 2FA webpage https://jupyter-jsc.fz-juelich.de/2fa.
This is the corresponding confirmation email.

The 2-factor authentication was removed for your account. You can request it again at any time.

Please delete the corresponding entry in your OTP-App. Even if you reactivate 2FA again, it will not regain its validity.

Best regards
Your Jupyter-JSC Team
    """
    send_mail(to, subject, text)
