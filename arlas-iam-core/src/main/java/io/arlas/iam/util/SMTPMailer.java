/*
 * Licensed to Gisaïa under one or more contributor
 * license agreements. See the NOTICE.txt file distributed with
 * this work for additional information regarding copyright
 * ownership. Gisaïa licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.arlas.iam.util;

import freemarker.cache.FileTemplateLoader;
import freemarker.cache.TemplateLoader;
import freemarker.template.Configuration;
import freemarker.template.TemplateException;
import io.arlas.iam.exceptions.SendEmailException;
import io.arlas.iam.model.User;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;

public class SMTPMailer {
    private final Logger LOGGER = LoggerFactory.getLogger(SMTPMailer.class);
    private final SMTPConfiguration conf;
    private final Session session;
    private Configuration freemarkerConf = null;

    public SMTPMailer(SMTPConfiguration conf) {
        this.conf = conf;
        if (conf.activated) {
            Properties props = System.getProperties();
            props.put("mail.smtp.host", conf.host);
            props.put("mail.smtp.port", conf.port);
            props.put("mail.smtp.auth", "true");
            if (conf.port.equals("587")) {
                props.put("mail.smtp.starttls.enable", "true");
            }
            this.session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(conf.username, conf.password);
                }
            });
            try {
                this.freemarkerConf = new Configuration(Configuration.VERSION_2_3_30);
                TemplateLoader templateLoader = new FileTemplateLoader(new File(conf.templateDir));
                freemarkerConf.setTemplateLoader(templateLoader);
            } catch (IOException e) {
                LOGGER.warn("Freemarker template dir not found. Will use hard coded mail content: " + conf.templateDir);
            }
        } else {
            this.session = null;
        }

    }

    public void sendActivationEmail(User to, String token) throws SendEmailException {
        if (this.conf.activated) {
            var messages = ResourceBundle.getBundle("messages", new Locale(to.getLocale()));
            sendEmail(to, messages.getString("email.verify.subject"), getActivationMailContent(to, token));
        } else {
            LOGGER.warn(String.format("SMTP client not activated. UserId: %s / Activation token: %s",
                    to.getId().toString(), token));
        }
    }

    public void sendPasswordResetEmail(User to, String token) throws SendEmailException {
        if (this.conf.activated) {
            var messages = ResourceBundle.getBundle("messages", new Locale(to.getLocale()));
            sendEmail(to, messages.getString("email.reset.subject"), getPasswordResetMailContent(to, token));
        } else {
            LOGGER.warn(String.format("SMTP client not activated. Reset token: %s", token));
        }
    }

    private void sendEmail(User to, String subject, String body) throws SendEmailException {
        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(this.conf.from));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to.getEmail()));
            message.setSubject(subject);

            var mimeBodyPart = new MimeBodyPart();
            mimeBodyPart.setContent(body, "text/html; charset=utf-8");

            var multipart = new MimeMultipart();
            multipart.addBodyPart(mimeBodyPart);

            message.setContent(multipart);
            Transport.send(message);
        } catch (MessagingException e) {
            LOGGER.error("Error sending email", e);
            throw new SendEmailException("Could not send email");
        }
    }

    private String getActivationMailContent(User to, String token) {
        var link = String.format(this.conf.verifyLink, to.getId().toString(), token);
        if (this.freemarkerConf != null) {
            try {
                var mailTemplate = freemarkerConf.getTemplate(conf.verifyTemplateFile, new Locale(to.getLocale()));
                var params = new HashMap<String, String>();
                params.put("link", link);
                Writer out = new StringWriter();
                mailTemplate.process(params, out);
                return out.toString();
            } catch (TemplateException | IOException e) {
                LOGGER.warn("Exception while processing email template. Will use hard coded mail content", e);
            }
        }
        return "Follow this link to verify your email and set your password: " + link;
    }

    private String getPasswordResetMailContent(User to, String token) {
        var link = String.format(this.conf.resetLink, to.getId().toString(), token);
        if (this.freemarkerConf != null) {
            try {
                var mailTemplate = freemarkerConf.getTemplate(conf.resetTemplateFile, new Locale(to.getLocale()));
                var params = new HashMap<String, String>();
                params.put("link", link);
                Writer out = new StringWriter();
                mailTemplate.process(params, out);
                return out.toString();
            } catch (TemplateException | IOException e) {
                LOGGER.warn("Exception while processing email template. Will use hard coded mail content", e);
            }
        }
        return "Follow this link to verify your email and set your password: " + link;
    }
}
