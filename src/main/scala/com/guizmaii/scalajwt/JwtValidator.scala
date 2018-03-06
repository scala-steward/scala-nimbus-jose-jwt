package com.guizmaii.scalajwt

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.BadJWTException

final case class JwtToken(content: String) extends AnyVal

sealed abstract class JwtValidationException(message: String) extends BadJWTException(message)
case object EmptyJwtTokenContent                              extends JwtValidationException("Empty JWT token")
case object InvalidRemoteJwkSet                               extends JwtValidationException("Cannot retrieve remote JWK set")
case object InvalidJwtToken                                   extends JwtValidationException("Invalid JWT token")
case object MissingExpirationClaim                            extends JwtValidationException("Missing `exp` claim")
case object InvalidTokenUseClaim                              extends JwtValidationException("Invalid `token_use` claim")
case object InvalidTokenIssuerClaim                           extends JwtValidationException("Invalid `iss` claim")
case object InvalidTokenSubject                               extends JwtValidationException("Invalid `sub` claim")
case object InvalidAudienceClaim                              extends JwtValidationException("Invalid `aud` claim")
case class UnknownException(exception: Exception)             extends JwtValidationException("Unknown JWT validation error")

trait JwtValidator {
  def validate(jwtToken: JwtToken): Either[BadJWTException, (JwtToken, JWTClaimsSet)]
}
