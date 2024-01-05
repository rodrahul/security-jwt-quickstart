package org.acme.security.jwt;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import io.quarkus.oidc.UserInfo;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.common.annotation.RunOnVirtualThread;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;

@Path("/secured")
@Produces(MediaType.TEXT_PLAIN)
@RequestScoped
@RunOnVirtualThread
public class TokenSecuredResource {

  @Inject
  JsonWebToken jwt;

  @Inject
  SecurityIdentity securityIdentity;

  @Inject
  @Claim("groups")
  Set<String> groups;

  @Inject
  Logger logger;

  @GET()
  @Path("/permit-all")
  @PermitAll
  public String hello(@Context SecurityContext ctx) {
    return getResponseString(ctx);
  }

  @GET
  @Path("roles-allowed")
  @RolesAllowed({ "Everyone", "Admin" })
  @Produces(MediaType.TEXT_PLAIN)
  public String helloRolesAllowed(@Context SecurityContext ctx) {
    logger.info(groups);
    UserInfo userinfo = securityIdentity.getAttribute("userinfo");
    logger.info(userinfo.getUserInfoString());
    logger.info(userinfo.getAllProperties());
    logger.info(Instant.ofEpochSecond(jwt.getExpirationTime()));
    return getResponseString(ctx);
  }

  @GET
  @Path("roles-allowed-admin")
  @RolesAllowed("Admin")
  @Produces(MediaType.TEXT_PLAIN)
  public String helloRolesAllowedAdmin(@Context SecurityContext ctx) {
    return getResponseString(ctx);
  }

  private String getResponseString(SecurityContext ctx) {
    String name;
    if (ctx.getUserPrincipal() == null) {
      name = "anonymous";
    } else if (!ctx.getUserPrincipal().getName().equals(jwt.getName())) {
      throw new InternalServerErrorException("Principal and JsonWebToken names do not match");
    } else {
      name = ctx.getUserPrincipal().getName();
    }
    return String.format("hello + %s,"
        + " isHttps: %s,"
        + " authScheme: %s,"
        + " hasJWT: %s",
        name, ctx.isSecure(), ctx.getAuthenticationScheme(), hasJwt());
  }

  private boolean hasJwt() {
    return jwt.getClaimNames() != null;
  }

}
