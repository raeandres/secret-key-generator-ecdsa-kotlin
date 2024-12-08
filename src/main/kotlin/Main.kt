package org.example

import com.google.crypto.tink.hybrid.HybridConfig
import org.kohsuke.args4j.CmdLineException
import org.kohsuke.args4j.CmdLineParser
import java.security.GeneralSecurityException
import kotlin.system.exitProcess

fun main(args: Array<String>) {

    HybridConfig.register()

    val keyUtil = KeyUtil()
    val parser = CmdLineParser(keyUtil)

    try {
        parser.parseArgument(*args)
    } catch (e: CmdLineException) {
        println(e)
        e.parser.printUsage(System.out)
        exitProcess(1)
    }
    try {
        keyUtil.keyCommand!!.run()
    } catch (e: GeneralSecurityException) {
        println("Cannot encrypt or decrypt, got error: $e")
        exitProcess(1)
    }
}