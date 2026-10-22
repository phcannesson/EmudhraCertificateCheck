package com.phcannesson.certificatecheck

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.phcannesson.certificatecheck.ui.theme.CertificateCheckTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException

private const val INCIDENT_URL = "https://emudhra.we-have-a-problem.com/"

private const val EMSIGN_ROOT = "emSign Root TLS CA - G3"
private const val AAA_ROOT = "AAA Certificate Services"

private data class TestHost(val host: String, val label: String, val root: String)

// Each revoked intermediate is served twice: chaining to its emSign root, then
// via the Sectigo cross-sign chaining to AAA Certificate Services.
private val HOSTS = listOf(
    TestHost("dv-g3b-emudhra.we-have-a-problem.com", "CN=EM DV TLS CA - G3B, O=eMudhra BV, C=NL", EMSIGN_ROOT),
    TestHost("dv-g3c-emudhra.we-have-a-problem.com", "CN=EM DV TLS CA - G3C, O=eMudhra Inc, C=US", EMSIGN_ROOT),
    TestHost("ov-g3b-emudhra.we-have-a-problem.com", "CN=EM OV TLS CA - G3B, O=eMudhra BV, C=NL", EMSIGN_ROOT),
    TestHost("ov-g3c-emudhra.we-have-a-problem.com", "CN=EM OV TLS CA - G3C, O=eMudhra Inc, C=US", EMSIGN_ROOT),
    TestHost("ev-g3b-emudhra.we-have-a-problem.com", "CN=EM EV TLS CA - G3B, O=eMudhra BV, C=NL", EMSIGN_ROOT),
    TestHost("ev-g3c-emudhra.we-have-a-problem.com", "CN=EM EV TLS CA - G3C, O=eMudhra Inc, C=US", EMSIGN_ROOT),
    TestHost("dv-g3b-aaa-emudhra.we-have-a-problem.com", "CN=EM DV TLS CA - G3B, O=eMudhra BV, C=NL", AAA_ROOT),
    TestHost("dv-g3c-aaa-emudhra.we-have-a-problem.com", "CN=EM DV TLS CA - G3C, O=eMudhra Inc, C=US", AAA_ROOT),
    TestHost("ov-g3b-aaa-emudhra.we-have-a-problem.com", "CN=EM OV TLS CA - G3B, O=eMudhra BV, C=NL", AAA_ROOT),
    TestHost("ov-g3c-aaa-emudhra.we-have-a-problem.com", "CN=EM OV TLS CA - G3C, O=eMudhra Inc, C=US", AAA_ROOT),
    TestHost("ev-g3b-aaa-emudhra.we-have-a-problem.com", "CN=EM EV TLS CA - G3B, O=eMudhra BV, C=NL", AAA_ROOT),
    TestHost("ev-g3c-aaa-emudhra.we-have-a-problem.com", "CN=EM EV TLS CA - G3C, O=eMudhra Inc, C=US", AAA_ROOT),
)

private val httpClient = OkHttpClient.Builder()
    .callTimeout(10, TimeUnit.SECONDS)
    .build()

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            CertificateCheckTheme {
                CertificateCheckScreen()
            }
        }
    }
}

private sealed interface ProbeResult {
    data object NotChecked : ProbeResult
    data object Checking : ProbeResult
    /** TLS handshake succeeded: the client trusts the compromised chain. */
    data class Insecure(val httpCode: Int) : ProbeResult
    /** TLS handshake was rejected. */
    data class Blocked(val reason: String) : ProbeResult
    /** Timeout or non-TLS network error: no conclusion possible. */
    data class Inconclusive(val reason: String) : ProbeResult
}

private fun probe(host: String): ProbeResult = try {
    val request = Request.Builder()
        .url("https://$host/?t=${System.currentTimeMillis()}")
        .header("Cache-Control", "no-store")
        .build()
    // Any HTTP response, even an error, means the TLS handshake succeeded.
    httpClient.newCall(request).execute().use { ProbeResult.Insecure(it.code) }
} catch (e: SSLException) {
    ProbeResult.Blocked(rootMessage(e))
} catch (e: InterruptedIOException) {
    ProbeResult.Inconclusive("timed out")
} catch (e: Exception) {
    ProbeResult.Inconclusive(rootMessage(e))
}

private fun rootMessage(e: Throwable): String {
    val root = generateSequence(e) { it.cause }.last()
    return root.message ?: root.javaClass.simpleName
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CertificateCheckScreen() {
    val results = remember { mutableStateListOf<ProbeResult>().apply { repeat(HOSTS.size) { add(ProbeResult.NotChecked) } } }
    var running by remember { mutableStateOf(false) }
    var hasRun by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    val run: suspend () -> Unit = {
        running = true
        HOSTS.indices.forEach { results[it] = ProbeResult.Checking }
        coroutineScope {
            HOSTS.mapIndexed { i, h ->
                async {
                    results[i] = withContext(Dispatchers.IO) { probe(h.host) }
                }
            }.awaitAll()
        }
        hasRun = true
        running = false
    }

    LaunchedEffect(Unit) { run() }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("eMudhra Intermediate CA Compromise", style = MaterialTheme.typography.titleLarge)
                    }
                }
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                Text(
                    "Does this device still trust the compromised intermediates?",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.size(4.dp))
                Text(
                    buildAnnotatedString {
                        append("The private keys of eight eMudhra intermediate CA certificates have been compromised and revoked. " +
                            "This app tries to connect to a test server for each revoked chain. A certificate error means " +
                            "the device does not trust the compromised intermediate. Details: ")
                        withLink(LinkAnnotation.Url(INCIDENT_URL, linkStyles())) { append(INCIDENT_URL) }
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
            }
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Button(onClick = { scope.launch { run() } }, enabled = !running) {
                        Text(if (hasRun) "Run again" else "Run check")
                    }
                    Spacer(Modifier.width(12.dp))
                    if (running) CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                }
                if (hasRun && !running) {
                    Spacer(Modifier.size(4.dp))
                    Text(summary(results), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                }
            }
            itemsIndexed(HOSTS) { i, host -> HostRow(host, results[i]) }
        }
    }
}

@Composable
private fun linkStyles() = TextLinkStyles(
    style = SpanStyle(color = MaterialTheme.colorScheme.primary, textDecoration = TextDecoration.Underline)
)

private fun summary(results: List<ProbeResult>): String {
    val insecure = results.count { it is ProbeResult.Insecure }
    val unknown = results.count { it is ProbeResult.Inconclusive }
    return "This device trusted $insecure of ${results.size} compromised certificate chains." +
        if (unknown > 0) " $unknown inconclusive, so the result is incomplete. Please try again later." else ""
}

@Composable
private fun HostRow(host: TestHost, result: ProbeResult) {
    val (text, color) = when (result) {
        ProbeResult.NotChecked -> "not yet checked" to MaterialTheme.colorScheme.onSurfaceVariant
        ProbeResult.Checking -> "checking…" to MaterialTheme.colorScheme.onSurfaceVariant
        is ProbeResult.Insecure ->
            (if (result.httpCode in 200..299) "❌ Insecure" else "❌ Insecure (HTTP ${result.httpCode})") to Color(0xFFC62828)
        is ProbeResult.Blocked -> "✅ Did not connect" to Color(0xFF2E7D32)
        is ProbeResult.Inconclusive -> "⚠️ Inconclusive (${result.reason})" to Color(0xFFEF6C00)
    }
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                buildAnnotatedString {
                    withLink(LinkAnnotation.Url("https://${host.host}/", linkStyles())) { append(host.label) }
                },
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium
            )
            Text("Chains to: ${host.root}", style = MaterialTheme.typography.bodySmall)
            Text(host.host, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(text, color = color, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            if (result is ProbeResult.Blocked) {
                Text(result.reason, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun HostRowPreview() {
    CertificateCheckTheme {
        HostRow(HOSTS[0], ProbeResult.Blocked("Trust anchor for certification path not found."))
    }
}
