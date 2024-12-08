package org.example

import com.google.crypto.tink.*
import com.google.crypto.tink.signature.SignatureKeyTemplates
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.kohsuke.args4j.Argument
import org.kohsuke.args4j.Option
import org.kohsuke.args4j.spi.SubCommand
import org.kohsuke.args4j.spi.SubCommandHandler
import org.kohsuke.args4j.spi.SubCommands
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.security.*
import java.util.*

class KeyUtil {

    interface KeyCommand {
        fun run()
    }

    open class PairOptions {

        @Option(name = "--keyType", required = true, usage = "Key Type (public / private)")
        val type = String

        @Option(name = "--env", required = true, usage = "Environment name")
        val environment = String

        @Option(name = "--country", required = true, usage = "Country prefix")
        val country = String
    }

    sealed class KeyType{
        data object PRIVATE: KeyType()
        data object PUBLIC: KeyType()
    }

    class GeneratePublicPair : PairOptions(),KeyCommand{

        override fun run() {

            if (type.equals("public")) {
                createPairFile(generateKey()!!, KeyType.PUBLIC, environment.toString(), country.toString(), ".b64")
            }

            if (type.equals("private")) {
                createPairFile(generateKey()!!, KeyType.PRIVATE, environment.toString(), country.toString(), ".b64")
            }
        }


        private fun generateKey(): KeyPair?  {

            Security.addProvider(BouncyCastleProvider())

            try {
                val eSpec : ECParameterSpec = ECNamedCurveTable.getParameterSpec("B-571")
                val keyGen : KeyPairGenerator = KeyPairGenerator.getInstance("ECDSA","BC")
                val random : SecureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN")

                keyGen.initialize(eSpec,random)

                return keyGen.generateKeyPair()
            } catch (exc: Exception) {
                exc.printStackTrace()
            } catch (e1: NoSuchAlgorithmException) {
                e1.printStackTrace()
            } catch (e2: NoSuchProviderException) {
                e2.printStackTrace()
            }

            return null
        }

        @Throws(IOException::class)
        fun createPairFile(keyPair: KeyPair, keyType: KeyType, envName:String, countryName: String, fileExtension: String) {

            var outputFile: File
            var stream : OutputStream

            when (keyType) {
                KeyType.PRIVATE -> {
                    outputFile = File("PRIVATE_ $envName" + "_$countryName$fileExtension")
                    stream = FileOutputStream(outputFile)

                    stream.use {
                        it.write(keyPair.private.encoded)
                    }
                }

                KeyType.PUBLIC -> {
                    outputFile = File("PUBLIC_ $envName" + "_$countryName$fileExtension")
                    stream = FileOutputStream(outputFile)

                    stream.use {
                        it.write(keyPair.public.encoded)
                    }
                }
            }

        }

    }


    open class Options {

        @Option(name = "--keyset", required = true, usage = "Keyset Output File")
        var keyset: File? = null

        @Option(name = "--from", required = true, usage = "Target source file")
        var inFile: File? = null

        @Option(name = "--env", required = true, usage = "Environment name")
        var environment: String? = null

        @Option(name = "--country", required = true, usage = "Country prefix")
        var country: String? = null

        @Option(name = "--extension", required = true, usage = "For assigning a file extension to the created signed file")
        var extension: String? = null

    }


    class Encrypt : Options(), KeyCommand {
        override fun run() {
            createSignedFile(signECDSAKeySet(generateKeysetHandle(keyset!!),inFile!!),environment.toString(),country.toString(),".$extension")
        }


        @Throws(IOException::class)
        fun createSignedFile(signedKeySet: ByteArray?, envName: String, countryName: String, fileExtension: String) {
            val signedOutFile = File(envName + "_" + countryName + fileExtension)

            val stream = FileOutputStream(signedOutFile)

            val signedKeySetToBase64 = Base64.getEncoder().encodeToString(signedKeySet)

            stream.use {
                it.write(signedKeySetToBase64.toByteArray())
            }
        }

        @Throws(GeneralSecurityException::class, IOException::class)
        fun generateKeysetHandle(keyset: File): KeysetHandle {
            if (keyset.exists()) {
                return CleartextKeysetHandle.read(JsonKeysetReader.withFile(keyset))
            }
            val handle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256)
            CleartextKeysetHandle.write(handle, JsonKeysetWriter.withFile(keyset))
            return handle
        }


        @Throws(IOException::class)
        fun signECDSAKeySet(keySetHandle: KeysetHandle, input: File) : ByteArray? {

            try {
                println("Private Key: $keySetHandle")


                // 2. Get the primitive.
                val signer: PublicKeySign = keySetHandle.getPrimitive(PublicKeySign::class.java)

                // 3. Use the primitive to sign.
                return signer.sign(java.nio.file.Files.readAllBytes(input.toPath()))
            } catch (exc: GeneralSecurityException) {
                exc.printStackTrace()
            }

            return null
        }

    }


    @Argument(metaVar = "command", required = true, handler = SubCommandHandler::class, usage = "The subcommand to run")
    @SubCommands(
        SubCommand(name = "genkeypair", impl = GeneratePublicPair::class),
        SubCommand(name = "encrypt", impl = Encrypt::class)
    )
    var keyCommand: KeyCommand? = null
}