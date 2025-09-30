package org.gluu.agama.update;

import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.EncryptionService;
import io.jans.as.common.service.common.UserService;
import io.jans.orm.exception.operation.EntryNotFoundException;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
// import org.gluu.agama.smtp.jans.service.JansEmailService;

import org.gluu.agama.user.EmailUpdate;
import io.jans.agama.engine.script.LogUtils;
import java.io.IOException;
import io.jans.as.common.service.common.ConfigurationService;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.regex.Pattern;
// Import for MailService and Smtp config
import io.jans.model.SmtpConfiguration;
import io.jans.service.MailService;

import org.gluu.agama.smtp.*;


import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jans.as.server.service.token.TokenService;
import io.jans.as.server.model.common.AuthorizationGrant;
import io.jans.as.server.model.common.AuthorizationGrantList;
import io.jans.as.server.model.common.AbstractToken;

public class JansEmailUpdate extends EmailUpdate {
    private static final Logger logger = LoggerFactory.getLogger(JansEmailUpdate.class);

    private static final String MAIL = "mail";
    private static final String UID = "uid";
    private static final String DISPLAY_NAME = "displayName";
    private static final String GIVEN_NAME = "givenName";
    private static final String LAST_NAME = "sn";
    private static final String PASSWORD = "userPassword";
    private static final String INUM_ATTR = "inum";
    private static final String EXT_ATTR = "jansExtUid";
    private static final String USER_STATUS = "jansStatus";
    private static final String EXT_UID_PREFIX = "github:";
    private static final String LANG = "lang";
    private static final SecureRandom RAND = new SecureRandom();
    private static final int OTP_LENGTH = 6;
    private static final String SUBJECT_TEMPLATE = "Here's your verification code: %s";
    private static final String MSG_TEMPLATE_TEXT = "%s is the code to complete your verification";

    private static JansEmailUpdate INSTANCE = null;

    public JansEmailUpdate() {
    }

    public static synchronized JansEmailUpdate getInstance() {
        if (INSTANCE == null)
            INSTANCE = new JansEmailUpdate();

        return INSTANCE;
    }

    public static Map<String, Object> validateBearerToken(String access_token) {
        Map<String, Object> result = new HashMap<>();

        try {
            if (access_token == null || access_token.trim().isEmpty()) {
                result.put("valid", false);
                result.put("errorMessage", "Access token is missing");
                return result;
            }

            // Get AuthorizationGrantList service
            AuthorizationGrantList authorizationGrantList = CdiUtil.bean(AuthorizationGrantList.class);
            if (authorizationGrantList == null) {
                result.put("valid", false);
                result.put("errorMessage", "Service not available");
                return result;
            }

            // Get the grant for this token
            AuthorizationGrant grant = authorizationGrantList.getAuthorizationGrantByAccessToken(access_token.trim());

            if (grant == null) {
                // Token not found
                result.put("valid", false);
                result.put("errorMessage", "Access token is invalid or expired");
                return result;
            }

            // Get the actual token object to check if it's valid (not expired)
            AbstractToken tokenObject = grant.getAccessToken(access_token.trim());

            // Check if token is active (exists and is valid)
            boolean isActive = tokenObject != null && tokenObject.isValid();

            if (isActive) {
                result.put("valid", true);
            } else {
                result.put("valid", false);
                result.put("errorMessage", "Access token is invalid or expired");
            }

        } catch (Exception e) {
            result.put("valid", false);
            result.put("errorMessage", "Access token is invalid or expired");
        }

        return result;
    }

    public boolean passwordPolicyMatch(String userPassword) {
        String regex = '''^(?=.*[!@#$^&*])[A-Za-z0-9!@#$^&*]{6,}$'''
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userPassword).matches();
    }

    public boolean usernamePolicyMatch(String userName) {
        // Regex: Only alphabets (uppercase and lowercase), minimum 1 character
        String regex = '''^[A-Za-z]+$''';
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userName).matches();
    }

    public Map<String, String> getUserEntityByMail(String email) {
        User user = getUser(MAIL, email);
        boolean local = user != null;
        // LogUtils.log("There is % local account for %", local ? "a" : "no", email);
        logger.debug("There is {} local account for {}", local ? "a" : "no", email);

        if (local) {
            String uid = getSingleValuedAttr(user, UID);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }

            // Creating a truly modifiable map
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);

            return userMap;
        }

        return new HashMap<>();
    }

    public Map<String, String> getUserEntityByUsername(String username) {
        User user = getUser(UID, username);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", username);

        if (local) {
            String email = getSingleValuedAttr(user, MAIL);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String uid = getSingleValuedAttr(user, UID); // Define uid properly
            String displayName = getSingleValuedAttr(user, DISPLAY_NAME);
            String givenName = getSingleValuedAttr(user, GIVEN_NAME);
            String sn = getSingleValuedAttr(user, LAST_NAME);
            String lang = getSingleValuedAttr(user, LANG);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }
            // Creating a modifiable HashMap directly
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);
            userMap.put(DISPLAY_NAME, displayName);
            userMap.put(LAST_NAME, sn);
            userMap.put(LANG, lang);

            return userMap;
        }

        return new HashMap<>();
    }

    public String addNewUser(Map<String, String> profile) throws Exception {
        Set<String> attributes = Set.of("uid", "mail", "displayName", "givenName", "sn", "userPassword");
        User user = new User();

        attributes.forEach(attr -> {
            String val = profile.get(attr);
            if (StringHelper.isNotEmpty(val)) {
                user.setAttribute(attr, val);
            }
        });

        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.addUser(user, true); // Set user status active

        if (user == null) {
            throw new EntryNotFoundException("Added user not found");
        }

        return getSingleValuedAttr(user, INUM_ATTR);
    }

    public String updateUser(Map<String, String> profile) throws Exception {
        Set<String> attributes = Set.of("uid", "mail");
        User user = getUser(INUM_ATTR, profile.get(INUM_ATTR));

        attributes.forEach(attr -> {
            String val = profile.get(attr);
            LogUtils.log("******** attr: % , val: %", attr, val);
            if (StringHelper.isNotEmpty(val)) {
                user.setAttribute(attr, val);
            }
        });
        user.setUserId(profile.get(UID));
        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.updateUser(user); // Set user status active

        if (user == null) {
            throw new EntryNotFoundException("Added user not found");
        }

        return getSingleValuedAttr(user, INUM_ATTR);
    }

    public Map<String, String> getUserEntityByInum(String inum) {
        User user = getUser(INUM_ATTR, inum);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", inum);

        if (local) {
            String email = getSingleValuedAttr(user, MAIL);
            // String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String uid = getSingleValuedAttr(user, UID); // Define uid properly
            String displayName = getSingleValuedAttr(user, DISPLAY_NAME);
            String givenName = getSingleValuedAttr(user, GIVEN_NAME);
            String sn = getSingleValuedAttr(user, LAST_NAME);
            String userPassword = getSingleValuedAttr(user, PASSWORD);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }
            // Creating a modifiable HashMap directly
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);
            userMap.put(DISPLAY_NAME, displayName);
            userMap.put(LAST_NAME, sn);
            userMap.put(PASSWORD, userPassword);

            return userMap;
        }

        return new HashMap<>();
    }

    public String sendEmail(String to, String lang) {
        try {
            // Fetch SMTP configuration
            ConfigurationService configService = CdiUtil.bean(ConfigurationService.class);
            SmtpConfiguration smtpConfig = configService.getConfiguration().getSmtpConfiguration();

            if (smtpConfig == null) {
                LogUtils.log("SMTP configuration is missing.");
                return null;
            }

            // Preferred language from user profile or fallback to English
            String preferredLang = (lang != null && !lang.isEmpty())
                    ? lang.toLowerCase()
                    : "en";

            // Generate OTP
            StringBuilder otpBuilder = new StringBuilder();
            for (int i = 0; i < OTP_LENGTH; i++) {
                otpBuilder.append(RAND.nextInt(10)); // Generates 0–9
            }
            String otp = otpBuilder.toString();

            // Select correct template
            Map<String, String> templateData;
            switch (preferredLang) {
                case "ar":
                    templateData = EmailOtpAr.get(otp);
                    break;
                case "es":
                    templateData = EmailOtpEs.get(otp);
                    break;
                case "fr":
                    templateData = EmailOtpFr.get(otp);
                    break;
                case "id":
                    templateData = EmailOtpId.get(otp);
                    break;
                case "pt":
                    templateData = EmailOtpPt.get(otp);
                    break;
                default:
                    templateData = EmailOtpEn.get(otp);
                    break;
            }

            String subject = templateData.get("subject");
            String htmlBody = templateData.get("body");
            String textBody = htmlBody.replaceAll("\\<.*?\\>", ""); // crude HTML → text

            // Send signed email
            MailService mailService = CdiUtil.bean(MailService.class);
            boolean sent = mailService.sendMailSigned(
                    smtpConfig.getFromEmailAddress(),
                    smtpConfig.getFromName(),
                    to,
                    null,
                    subject,
                    textBody,
                    htmlBody);

            if (sent) {
                LogUtils.log("Localized OTP email sent successfully to %", to);
                return otp;
            } else {
                LogUtils.log("Failed to send localized OTP email to %", to);
                return null;
            }

        } catch (Exception e) {
            LogUtils.log("Failed to send OTP email: %", e.getMessage());
            return null;
        }
    }

    public String sendEmailUpdateSuccess(String to, String lang) {
        try {
            // Fetch SMTP configuration
            ConfigurationService configService = CdiUtil.bean(ConfigurationService.class);
            SmtpConfiguration smtpConfig = configService.getConfiguration().getSmtpConfiguration();

            if (smtpConfig == null) {
                LogUtils.log("SMTP configuration is missing.");
                return null;
            }

            // Preferred language or fallback to English
            String preferredLang = (lang != null && !lang.isEmpty())
                    ? lang.toLowerCase()
                    : "en";

            // Pick localized email template
            Map<String, String> templateData;
            switch (preferredLang) {
                case "ar":
                    templateData = EmailUpdateSuccessAr.get();
                    break;
                case "es":
                    templateData = EmailUpdateSuccessEs.get();
                    break;
                case "fr":
                    templateData = EmailUpdateSuccessFr.get();
                    break;
                case "id":
                    templateData = EmailUpdateSuccessId.get();
                    break;
                case "pt":
                    templateData = EmailUpdateSuccessPt.get();
                    break;
                default:
                    templateData = EmailUpdateSuccessEn.get();
                    break;
            }

            String subject = templateData.get("subject");
            String htmlBody = templateData.get("body");
            String textBody = htmlBody.replaceAll("\\<.*?\\>", "");

            // Send email
            MailService mailService = CdiUtil.bean(MailService.class);
            boolean sent = mailService.sendMailSigned(
                    smtpConfig.getFromEmailAddress(),
                    smtpConfig.getFromName(),
                    to,
                    null,
                    subject,
                    textBody,
                    htmlBody);

            if (sent) {
                LogUtils.log("Localized email update success mail sent to %", to);
                return "SUCCESS";
            } else {
                LogUtils.log("Failed to send email update success mail to %", to);
                return null;
            }

        } catch (Exception e) {
            LogUtils.log("Failed to send email update success mail: %", e.getMessage());
            return null;
        }
    }

    private String getSingleValuedAttr(User user, String attribute) {
        Object value = null;
        if (attribute.equals(UID)) {
            // user.getAttribute("uid", true, false) always returns null :(
            value = user.getUserId();
        } else {
            value = user.getAttribute(attribute, true, false);
        }
        return value == null ? null : value.toString();

    }

    private SmtpConfiguration getSmtpConfiguration() {
        ConfigurationService configurationService = CdiUtil.bean(ConfigurationService.class);
        SmtpConfiguration smtpConfiguration = configurationService.getConfiguration().getSmtpConfiguration();
        return smtpConfiguration;

    }

    private User getUser(String attributeName, String value) {
        UserService userService = CdiUtil.bean(UserService.class);
        return userService.getUserByAttribute(attributeName, value, true);
    }
}
