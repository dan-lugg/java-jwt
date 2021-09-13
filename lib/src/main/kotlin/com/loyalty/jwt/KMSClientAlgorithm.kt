package com.loyalty.jwt

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.SignatureGenerationException
import com.auth0.jwt.exceptions.SignatureVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import java.nio.ByteBuffer
import java.util.Base64

class KMSClientAlgorithm(
    name: String,
    description: String,
    private val kmsClient: KMSClient,
    private val kmsKeyId: String,
    private val kmsSigningAlgorithm: String,
) : Algorithm(name, description)
{
    override fun verify(jwt: DecodedJWT)
    {
        lateinit var contentBytes: ByteArray
        lateinit var signatureBytes: ByteArray

        try
        {
            val decoder = Base64.getUrlDecoder()
            val headerBytes = decoder.decode(jwt.header)
            val payloadBytes = decoder.decode(jwt.payload)
            val dotByte = '.'.code.toByte()

            contentBytes = headerBytes.plus(dotByte).plus(payloadBytes)
            signatureBytes = decoder.decode(jwt.signature)
        }
        catch (exception: Exception)
        {
            throw SignatureVerificationException(this, exception)
        }

        if (!this.sign(contentBytes).contentEquals(signatureBytes))
        {
            throw SignatureVerificationException(this)
        }
    }

    override fun sign(contentBytes: ByteArray?): ByteArray
    {
        try
        {
            val messageByteBuffer = ByteBuffer.wrap(contentBytes)
            val signatureByteBuffer = this.kmsClient.sign(this.kmsKeyId, this.kmsSigningAlgorithm, messageByteBuffer)
            return signatureByteBuffer.array()
        }
        catch(exception:Exception)
        {
            throw SignatureGenerationException(this, exception)
        }
    }
}
