# Azure AD JWT token checker

Checking JWT tokens received from Microsoft Azure turned to be more complicated than I thought so I put together a small demonstration application in the hope that
others may find it useful. It is based on [Auth0's Java-jwt library](https://github.com/auth0/java-jwt) to do the actual verification but the interesting bit is
the extraction of Microsoft's public keys.

Note that this application is only able to decode and verify Azure Active Directory tokens and *not* Azure Active Directory v2.0 tokens. By my best knowledge the v2.0 token
structure has not been documented by Microsoft and Java-jwt can't decode these tokens.

If you don't know the difference between Azure AD and Azure AD v2.0 tokens, [read this](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code) 
and [this](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-appmodel-v2-overview).

# Build and run

`./gradlew run` will execute the application with a token embedded into the application. It will throw a TokenExpiredException as the token has obviously expired (but will dump the token's content
nevetheless).

`.gradlew run -Ptoken=eyJ0eXAiO ... MC5id0Iw` will execute the application with the specified token.

