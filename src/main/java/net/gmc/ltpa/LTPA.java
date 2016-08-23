package net.gmc.ltpa;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.*;

/**
 * @author Jaroslav Holan, jaroslav.holan@topmonks.com
 */
@Path("")
public class LTPA {

    @GET
    @Path("cookie")
    @Produces(MediaType.APPLICATION_JSON)
    public String getCookieValue(@Context HttpHeaders headers) {
        return headers.getCookies().toString();
    }

    @GET
    @Path("setcookie")
    @Produces(MediaType.TEXT_PLAIN)
    public Response get(@Context HttpHeaders h) {
        String cookieName = "LTPAToken";
        String cookieValue = "AAECAzU3YjQ1MWM0NTdiNDY5MzRNeSBUZXN0IFVzZXKJ2NS4iw2JTsJywolTa5pa6Y5kAA==";

        Cookie c = h.getCookies().get(cookieName);
        String e = (c == null) ? "NO-COOKIE" : c.getValue();
        return Response.ok(e).
                cookie(new NewCookie(cookieName, cookieValue)).build();
    }

    @GET
    @Path("decode")
    @Produces(MediaType.APPLICATION_JSON)
    public String decodeLtpaTokenFromCookie(@Context HttpHeaders headers) {
        Cookie cookie = headers.getCookies().get("LtpaToken2");
        String ltpaToken;
        if (cookie == null) {
            ltpaToken = "I0eVFRDLIp/iACeOdf6SXnyMg4MykAWixHjT5NqavV0MCiKVf+hhTFSeIuEd1Qs6CQaTlrgs63DyFBmtiSzCePUPK5" +
                    "cH42SYfeP8KgXOUL/rlfbkmS76lv/qNvkntuuwEdJe4msC2Bhw9n3ETd5LjqRioxjM0XTo0KCXyiSyn3QAMgIbzRunIWmR" +
                    "m456SxnBRZhYPY0IaYlJJ3dZGSXBnU0EFWOLOwbcEYjUFzfDL9g3SNS79Hk2a0BPZGgUqtHu9hy2tD5n8tt8stAw2TOimV" +
                    "0ZKitn2/meAFSHF1yOHAY1NYpHWa94affOr7d9ACJU";

        } else {
            ltpaToken = headers.getCookies().get("LtpaToken2").getValue();
        }
        String response;
        try {
            LtpaDecoder ltpaDecoder = new LtpaDecoder(ltpaToken);
            response = ltpaDecoder.getUserInfo();
        } catch (Exception e) {
            response = e.getMessage();
        }
        String message = "Try decode cookie LtpaToken2: " + ltpaToken
                + "\n\n Response: " + response;
        return message;
    }


}
