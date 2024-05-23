package dev.kryptonreborn.ed25519

import com.goncalossilva.resources.Resource
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
class WycheproofTestJson(
    val algorithm: String,
    val generatorVersion: String,
    val numberOfTests: Int,
    val header: List<String>,
    val notes: Map<String, String>,
    val schema: String,
    val testGroups: List<TestGroup>,
)

@Serializable
class TestGroup(
    val jwk: Jwk? = null,
    val key: Key,
    val keyDer: String,
    val keyPem: String,
    val type: String,
    val tests: List<TestCase>,
)

@Serializable
class TestCase(
    val tcId: Int,
    val comment: String,
    val msg: String,
    val sig: String,
    val result: String,
)

@Serializable
class Jwk(
    val crv: String,
    val d: String,
    val kid: String,
    val kty: String,
    val x: String,
)

@Serializable
class Key(
    val curve: String,
    val keySize: Int,
    val type: String,
    val pk: String? = null,
    val sk: String? = null,
    val uncompressed: String? = null,
    val wx: String? = null,
    val wy: String? = null,
)

fun loadEddsaTestJson(): WycheproofTestJson {
    val json =
        Json {
            ignoreUnknownKeys = true
        }

    return json.decodeFromString(Resource("src/commonTest/resources/wycheproof/eddsa_test.json").readText())
}
