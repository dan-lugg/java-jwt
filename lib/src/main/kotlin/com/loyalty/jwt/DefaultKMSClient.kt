package com.loyalty.jwt

import com.amazonaws.services.kms.AWSKMS
import com.amazonaws.services.kms.model.SignRequest
import com.amazonaws.services.kms.model.VerifyRequest
import java.nio.ByteBuffer

class DefaultKMSClient(
    private val awskms: AWSKMS,
) : KMSClient
{
    override fun sign(keyId: String, signingAlgorithm: String, message: ByteBuffer): ByteBuffer
    {
        val signRequest = SignRequest()
            .withSigningAlgorithm(signingAlgorithm)
            .withMessage(message)
            .withKeyId(keyId)
        return this.awskms.sign(signRequest).signature
    }

    override fun verify(keyId: String, signingAlgorithm: String, message: ByteBuffer): Boolean
    {
        val verifyRequest = VerifyRequest()
            .withSigningAlgorithm(signingAlgorithm)
            .withMessage(message)
            .withKeyId(keyId)
        return this.awskms.verify(verifyRequest).isSignatureValid
    }
}
