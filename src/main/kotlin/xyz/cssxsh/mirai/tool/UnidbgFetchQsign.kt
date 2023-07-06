package xyz.cssxsh.mirai.tool

import kotlinx.coroutines.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.json.*
import net.mamoe.mirai.internal.spi.*
import net.mamoe.mirai.utils.*
import org.asynchttpclient.*
import org.asynchttpclient.ws.*
import java.util.concurrent.*
import kotlin.coroutines.*

@OptIn(MiraiInternalApi::class)
public class UnidbgFetchQsign(private val server: String, private val key: String, coroutineContext: CoroutineContext)
    : EncryptService, CoroutineScope {

    override val coroutineContext: CoroutineContext =
        coroutineContext + SupervisorJob(coroutineContext[Job]) + CoroutineExceptionHandler { context, exception ->
            when (exception) {
                is kotlinx.coroutines.CancellationException -> {
                    // ...
                }
                else -> {
                    logger.warning({ "with ${context[CoroutineName]}" }, exception)
                }
            }
        }

    private val client = Dsl.asyncHttpClient(
        DefaultAsyncHttpClientConfig.Builder()
            .setKeepAlive(true)
            .setUserAgent("curl/7.61.0")
            .setRequestTimeout(30_000)
            .setConnectTimeout(30_000)
            .setReadTimeout(180_000)
    )

    private val token = java.util.concurrent.atomic.AtomicBoolean(false)

    private val white = mutableListOf<String>()

    public fun about(): String {
        val response = client.prepareGet(server)
            .execute().get()
        val body = json.decodeFromString(DataWrapper.serializer(), response.responseBody)
        check(body.code == 0) { body.message }

        return json.encodeToString(JsonElement.serializer(), body.data)
    }

    override fun initialize(context: EncryptServiceContext) {
        val device = context.extraArgs[EncryptServiceContext.KEY_DEVICE_INFO]
        val qimei36 = context.extraArgs[EncryptServiceContext.KEY_QIMEI36]
        val channel = context.extraArgs[EncryptServiceContext.KEY_CHANNEL_PROXY]

        register(uin = context.id, androidId = device.androidId.decodeToString(), guid = device.guid.toUHexString(), qimei36 = qimei36)
        white.addAll(getCmdWhiteList(uin = context.id))
        channelProxy(uin = context.id, channel = channel)
    }

    private fun register(uin: Long, androidId: String, guid: String, qimei36: String) {
        val response = client.prepareGet("${server}/register")
            .addQueryParam("uin", uin.toString())
            .addQueryParam("android_id", androidId)
            .addQueryParam("guid", guid)
            .addQueryParam("qimei36", qimei36)
            .addQueryParam("key", key)
            .execute().get()
        val body = json.decodeFromString(DataWrapper.serializer(), response.responseBody)
        check(body.code == 0) { body.message }

        logger.debug("Bot(${uin}) init, ${body.message}")
    }

    private fun requestToken(uin: Long) {
        val response = client.prepareGet("${server}/request_token")
            .addQueryParam("uin", uin.toString())
            .execute().get()
        val body = json.decodeFromString(DataWrapper.serializer(), response.responseBody)
        check(body.code == 0) { body.message }

        logger.debug("Bot(${uin}) requestToken, ${body.message}")
    }

    private fun channelProxy(uin: Long, channel: EncryptService.ChannelProxy) {
        val ws = "${server}/channel_proxy".replace("http", "ws")
        val listener = object : WebSocketListener {
            private lateinit var websocket: WebSocket

            override fun onOpen(websocket: WebSocket) {
                this.websocket = websocket
                logger.debug("Bot(${uin}) $ws open")
            }

            override fun onClose(websocket: WebSocket, code: Int, reason: String?) {
                logger.debug("Bot(${uin}) $ws close")
            }

            override fun onError(cause: Throwable) {
                logger.error("Bot(${uin}) $ws", cause)
            }

            override fun onTextFrame(payload: String, finalFragment: Boolean, rsv: Int) {
                launch(CoroutineName("SendMessage")) {
                    val packet = json.decodeFromString(SsoPacket.serializer(), payload)
                    logger.debug("Bot(${uin}) sendMessage <- ${packet.cmd}")

                    val result = channel.sendMessage(
                        remark = packet.remark,
                        commandName = packet.cmd,
                        uin = uin,
                        data = packet.body.hexToBytes()
                    )

                    if (result == null) {
                        logger.debug("Bot.${uin} ChannelResult is null")
                        return@launch
                    }
                    logger.debug("Bot(${uin}) sendMessage -> ${result.cmd}")
                    val r = SsoPacket(
                        remark = packet.remark,
                        cmd = result.cmd,
                        id = packet.id,
                        body = result.data.toUHexString("")
                    )

                    websocket.sendTextFrame(json.encodeToString(SsoPacket.serializer(), r))
                }
            }
        }
        val websocket = client.prepareGet(ws)
            .addQueryParam("uin", uin.toString())
            .execute(
                WebSocketUpgradeHandler
                    .Builder()
                    .addWebSocketListener(listener)
                    .build()
            )
            .get()
        coroutineContext[Job]?.invokeOnCompletion { websocket.sendCloseFrame() }
    }

    private fun getCmdWhiteList(uin: Long): List<String> {
        val response = client.prepareGet("${server}/get_cmd_white_list")
            .addQueryParam("uin", uin.toString())
            .execute().get()
        val body = json.decodeFromString(DataWrapper.serializer(), response.responseBody)
        check(body.code == 0) { body.message }

        logger.debug("Bot(${uin}) getCmdWhiteList, ${body.message}")

        return json.decodeFromJsonElement(ListSerializer(String.serializer()), body.data)
    }

    override fun encryptTlv(context: EncryptServiceContext, tlvType: Int, payload: ByteArray): ByteArray? {
        if (tlvType != 0x544) return null
        val command = context.extraArgs[EncryptServiceContext.KEY_COMMAND_STR]

        val data = customEnergy(uin = context.id, salt = payload, data = command)

        return data.hexToBytes()
    }

    private fun customEnergy(uin: Long, salt: ByteArray, data: String): String {
        val response = client.prepareGet("${server}/custom_energy")
            .addQueryParam("uin", uin.toString())
            .addQueryParam("salt", salt.toUHexString(""))
            .addQueryParam("data", data)
            .execute().get()
        val body = json.decodeFromString(DataWrapper.serializer(), response.responseBody)
        check(body.code == 0) { body.message }

        logger.debug("Bot(${uin}) energy ${data}, ${body.message}")

        return json.decodeFromJsonElement(String.serializer(), body.data)
    }

    override fun qSecurityGetSign(
        context: EncryptServiceContext,
        sequenceId: Int,
        commandName: String,
        payload: ByteArray
    ): EncryptService.SignResult? {
        if (commandName == "StatSvc.register") {
            if (!token.get() && token.compareAndSet(false, true)) {
                launch(CoroutineName("RequestToken")) {
                    requestToken(uin = context.id)
                }
            }
        }

        if (commandName !in white) return null

        val data = sign(uin = context.id, cmd = commandName, seq = sequenceId, buffer = payload)

        return EncryptService.SignResult(
            sign = data.sign.hexToBytes(),
            token = data.token.hexToBytes(),
            extra = data.extra.hexToBytes(),
        )
    }

    private fun sign(uin: Long, cmd: String, seq: Int, buffer: ByteArray) : SignResult {
        val response = client.preparePost("${server}/sign")
            .addFormParam("uin", uin.toString())
            .addFormParam("cmd", cmd)
            .addFormParam("seq", seq.toString())
            .addFormParam("buffer", buffer.toUHexString(""))
            .execute().get()
        val body = json.decodeFromString(DataWrapper.serializer(), response.responseBody)
        check(body.code == 0) { body.message }

        logger.debug("Bot(${uin}) getSign ${cmd}, ${body.message}")

        return json.decodeFromJsonElement(SignResult.serializer(), body.data)
    }

    public companion object {
        @JvmStatic
        internal val logger: MiraiLogger = MiraiLogger.Factory.create(UnidbgFetchQsign::class)

        internal val json = Json {
            prettyPrint = true
            isLenient = true
        }
    }
}

@Serializable
private data class DataWrapper(
    @SerialName("code")
    val code: Int = 0,
    @SerialName("msg")
    val message: String = "",
    @SerialName("data")
    val data: JsonElement
)

@Serializable
private data class SignResult(
    @SerialName("token")
    val token: String = "",
    @SerialName("extra")
    val extra: String = "",
    @SerialName("sign")
    val sign: String = "",
    @SerialName("o3did")
    val o3did: String = ""
)

@Serializable
@OptIn(ExperimentalSerializationApi::class)
private data class SsoPacket(
    @SerialName("remark")
    val remark: String,
    @SerialName("body")
    val body: String = "",
    @JsonNames("callback_id", "callbackId")
    val id: Int = 0,
    @SerialName("cmd")
    val cmd: String = ""
)