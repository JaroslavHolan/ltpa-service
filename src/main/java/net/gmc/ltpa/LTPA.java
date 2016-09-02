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
    @Path("decode")
    @Produces(MediaType.APPLICATION_JSON)
    public String decodeLtpaTokenFromCookie(@Context HttpHeaders headers) {
        Cookie cookie = headers.getCookies().get("LtpaToken2");
        String ltpaToken;
        if (cookie == null) {
            ltpaToken = "token not found";

        } else {
            ltpaToken = cookie.getValue();
        }
        String response;
        try {
            LtpaDecoder ltpaDecoder = new LtpaDecoder(ltpaToken);
            response = ltpaDecoder.getLtpaPlainText();
        } catch (Exception e) {
            response = e.getMessage();
        }
        String message = "Try decode cookie LtpaToken2: " + ltpaToken
                + "\n\n Response: " + response;
        return message;
    }


}
