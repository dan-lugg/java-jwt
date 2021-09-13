package com.loyalty.jwt

import java.nio.ByteBuffer

interface KMSClient
{
    fun sign(keyId: String, signingAlgorithm: String, message: ByteBuffer): ByteBuffer

    fun verify(keyId: String, signingAlgorithm: String, message: ByteBuffer): Boolean
}
