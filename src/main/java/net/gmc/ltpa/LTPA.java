package net.gmc.ltpa;

import javax.json.Json;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.*;
import java.security.Principal;

import static javax.ws.rs.core.Response.Status.OK;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

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

    @GET
    @Path("user")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserInfoInJson(@Context HttpServletRequest request) {
        Principal userPrincipal = request.getUserPrincipal();
        Response response;
        if (userPrincipal == null) {
            response = getErrorResponse();
        } else {
            response = getOkResponse(userPrincipal.getName());
        }
        return response;
    }

    private Response getErrorResponse() {
        String json = Json.createObjectBuilder()
                .add("error", "User is not logged.")
                .build().toString();
        return Response.status(UNAUTHORIZED).entity(json).build();
    }

    private Response getOkResponse(String username) {
        String json = Json.createObjectBuilder()
                .add("username", username)
                .build().toString();
        return Response.status(OK).entity(json).build();
    }


}
