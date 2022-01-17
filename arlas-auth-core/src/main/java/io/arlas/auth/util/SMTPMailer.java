package io.arlas.auth.util;

import io.arlas.auth.exceptions.SendEmailException;
import io.arlas.auth.model.User;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

public class SMTPMailer {
    Logger LOGGER = LoggerFactory.getLogger(SMTPMailer.class);
    private final SMTPConfiguration conf;
    private final Session session;

    public SMTPMailer(SMTPConfiguration conf) {
        this.conf = conf;
        if (conf.activated) {
            Properties props = System.getProperties();
            props.put("mail.smtp.host", conf.host);
            props.put("mail.smtp.port", conf.port);
            props.put("mail.smtp.auth", "true");
            this.session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(conf.username, conf.password);
                }
            });
        } else {
            this.session = null;
        }

    }

    public void sendEmail(User to, String token) throws SendEmailException {
        // TODO use templating to make email content configurable
        if (this.conf.activated) {
            try {
                Message message = new MimeMessage(session);
                message.setFrom(new InternetAddress(this.conf.from));
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to.getEmail()));
                message.setSubject("Please verify your email");

                String msg = String.format("Follow this link to verify your email and set your password: %s/%s",
                        this.conf.link, token);

                MimeBodyPart mimeBodyPart = new MimeBodyPart();
                mimeBodyPart.setContent(msg, "text/html; charset=utf-8");

                Multipart multipart = new MimeMultipart();
                multipart.addBodyPart(mimeBodyPart);

                message.setContent(multipart);
                Transport.send(message);
            } catch (MessagingException e) {
                LOGGER.error("Error sending email", e);
                throw new SendEmailException("Could not send email");
            }
        } else {
            LOGGER.warn(String.format("SMTP client not activated. Verification token: %s",token));
        }
    }
}
