// PhishGuardApiService.kt
// Android Retrofit API client for PhishGuard backend

import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.*
import com.google.gson.annotations.SerializedName
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import java.util.concurrent.TimeUnit

// ============================================================================
// Data Models (Request/Response DTOs)
// ============================================================================

data class ScanRequest(
    @SerializedName("message") val message: String,
    @SerializedName("user_id") val userId: String? = null,
    @SerializedName("device_id") val deviceId: String? = null
)

data class ScanResponse(
    @SerializedName("scan_id") val scanId: Int,
    @SerializedName("is_phishing") val isPhishing: Boolean,
    @SerializedName("risk_score") val riskScore: Double,
    @SerializedName("confidence") val confidence: String,
    @SerializedName("message") val message: String,
    @SerializedName("prediction_time_ms") val predictionTimeMs: Int,
    @SerializedName("timestamp") val timestamp: String
)

data class ScanHistoryResponse(
    @SerializedName("scans") val scans: List<ScanHistoryItem>,
    @SerializedName("total_count") val totalCount: Int,
    @SerializedName("limit") val limit: Int,
    @SerializedName("offset") val offset: Int,
    @SerializedName("has_more") val hasMore: Boolean
)

data class ScanHistoryItem(
    @SerializedName("id") val id: Int,
    @SerializedName("user_id") val userId: String?,
    @SerializedName("device_id") val deviceId: String?,
    @SerializedName("message_text") val messageText: String,
    @SerializedName("is_phishing") val isPhishing: Boolean,
    @SerializedName("risk_score") val riskScore: Double,
    @SerializedName("confidence_level") val confidenceLevel: String,
    @SerializedName("model_version") val modelVersion: String?,
    @SerializedName("prediction_time_ms") val predictionTimeMs: Int?,
    @SerializedName("created_at") val createdAt: String,
    @SerializedName("user_feedback") val userFeedback: String?
)

data class UserStatisticsResponse(
    @SerializedName("statistics") val statistics: UserStatistics,
    @SerializedName("status") val status: String
)

data class UserStatistics(
    @SerializedName("user_id") val userId: String,
    @SerializedName("total_scans") val totalScans: Int,
    @SerializedName("phishing_detected") val phishingDetected: Int,
    @SerializedName("safe_messages") val safeMessages: Int,
    @SerializedName("average_risk_score") val averageRiskScore: Double,
    @SerializedName("highest_risk_score") val highestRiskScore: Double,
    @SerializedName("first_scan_date") val firstScanDate: String?,
    @SerializedName("last_scan_date") val lastScanDate: String?,
    @SerializedName("feedback_provided") val feedbackProvided: Int,
    @SerializedName("correct_predictions") val correctPredictions: Int,
    @SerializedName("incorrect_predictions") val incorrectPredictions: Int
)

data class FeedbackRequest(
    @SerializedName("scan_id") val scanId: Int,
    @SerializedName("feedback") val feedback: String // CORRECT, INCORRECT, UNSURE
)

data class AnalyticsDashboard(
    @SerializedName("total_scans") val totalScans: Int,
    @SerializedName("phishing_detected") val phishingDetected: Int,
    @SerializedName("safe_messages") val safeMessages: Int,
    @SerializedName("phishing_rate") val phishingRate: Double,
    @SerializedName("average_risk_score") val averageRiskScore: Double,
    @SerializedName("scans_last_24h") val scansLast24h: Int,
    @SerializedName("total_users") val totalUsers: Int,
    @SerializedName("average_inference_time_ms") val averageInferenceTimeMs: Double,
    @SerializedName("model_version") val modelVersion: String,
    @SerializedName("timestamp") val timestamp: String
)

data class ErrorResponse(
    @SerializedName("error") val error: String,
    @SerializedName("status") val status: String
)


// ============================================================================
// Retrofit API Interface
// ============================================================================

interface PhishGuardApi {
    
    @POST("api/scan")
    suspend fun scanMessage(@Body request: ScanRequest): ScanResponse
    
    @GET("api/history")
    suspend fun getScanHistory(
        @Query("user_id") userId: String,
        @Query("limit") limit: Int = 50,
        @Query("offset") offset: Int = 0,
        @Query("phishing_only") phishingOnly: Boolean = false
    ): ScanHistoryResponse
    
    @GET("api/statistics/{user_id}")
    suspend fun getUserStatistics(@Path("user_id") userId: String): UserStatisticsResponse
    
    @POST("api/feedback")
    suspend fun submitFeedback(@Body request: FeedbackRequest): Map<String, String>
    
    @GET("api/analytics/dashboard")
    suspend fun getAnalyticsDashboard(): AnalyticsDashboard
    
    @GET("health")
    suspend fun healthCheck(): Map<String, Any>
}


// ============================================================================
// Retrofit Client Builder
// ============================================================================

object PhishGuardApiClient {
    
    private const val BASE_URL = "http://10.0.2.2:5000/" // Use this for Android emulator
    // For real device: private const val BASE_URL = "http://YOUR_SERVER_IP:5000/"
    
    private val loggingInterceptor = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.BODY
    }
    
    private val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(loggingInterceptor)
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()
    
    private val retrofit = Retrofit.Builder()
        .baseUrl(BASE_URL)
        .client(okHttpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
    
    val api: PhishGuardApi = retrofit.create(PhishGuardApi::class.java)
}


// ============================================================================
// Repository Pattern (Recommended for Clean Architecture)
// ============================================================================

class PhishGuardRepository {
    
    private val api = PhishGuardApiClient.api
    
    suspend fun scanMessage(
        message: String,
        userId: String? = null,
        deviceId: String? = null
    ): Result<ScanResponse> {
        return try {
            val request = ScanRequest(
                message = message,
                userId = userId,
                deviceId = deviceId
            )
            val response = api.scanMessage(request)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun getScanHistory(
        userId: String,
        limit: Int = 50,
        offset: Int = 0,
        phishingOnly: Boolean = false
    ): Result<ScanHistoryResponse> {
        return try {
            val response = api.getScanHistory(userId, limit, offset, phishingOnly)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun getUserStatistics(userId: String): Result<UserStatistics> {
        return try {
            val response = api.getUserStatistics(userId)
            Result.success(response.statistics)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun submitFeedback(scanId: Int, feedback: String): Result<Boolean> {
        return try {
            val request = FeedbackRequest(scanId, feedback)
            api.submitFeedback(request)
            Result.success(true)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun getAnalyticsDashboard(): Result<AnalyticsDashboard> {
        return try {
            val response = api.getAnalyticsDashboard()
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun checkHealth(): Result<Boolean> {
        return try {
            api.healthCheck()
            Result.success(true)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}


// ============================================================================
// ViewModel Example (for MVVM Architecture)
// ============================================================================

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class PhishGuardViewModel : ViewModel() {
    
    private val repository = PhishGuardRepository()
    
    // UI State for scan result
    private val _scanResult = MutableStateFlow<ScanResult?>(null)
    val scanResult: StateFlow<ScanResult?> = _scanResult
    
    // UI State for loading
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading
    
    // UI State for error
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error
    
    // UI State for scan history
    private val _scanHistory = MutableStateFlow<List<ScanHistoryItem>>(emptyList())
    val scanHistory: StateFlow<List<ScanHistoryItem>> = _scanHistory
    
    // UI State for user statistics
    private val _userStats = MutableStateFlow<UserStatistics?>(null)
    val userStats: StateFlow<UserStatistics?> = _userStats
    
    
    fun scanMessage(message: String, userId: String?, deviceId: String?) {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null
            
            repository.scanMessage(message, userId, deviceId)
                .onSuccess { response ->
                    _scanResult.value = ScanResult(
                        scanId = response.scanId,
                        isPhishing = response.isPhishing,
                        riskScore = response.riskScore,
                        confidence = response.confidence,
                        message = response.message,
                        predictionTimeMs = response.predictionTimeMs
                    )
                }
                .onFailure { exception ->
                    _error.value = "Error: ${exception.message}"
                }
            
            _isLoading.value = false
        }
    }
    
    fun loadScanHistory(userId: String, phishingOnly: Boolean = false) {
        viewModelScope.launch {
            _isLoading.value = true
            
            repository.getScanHistory(userId, limit = 50, phishingOnly = phishingOnly)
                .onSuccess { response ->
                    _scanHistory.value = response.scans
                }
                .onFailure { exception ->
                    _error.value = "Error loading history: ${exception.message}"
                }
            
            _isLoading.value = false
        }
    }
    
    fun loadUserStatistics(userId: String) {
        viewModelScope.launch {
            repository.getUserStatistics(userId)
                .onSuccess { stats ->
                    _userStats.value = stats
                }
                .onFailure { exception ->
                    _error.value = "Error loading statistics: ${exception.message}"
                }
        }
    }
    
    fun submitFeedback(scanId: Int, feedback: String) {
        viewModelScope.launch {
            repository.submitFeedback(scanId, feedback)
                .onSuccess {
                    // Optionally refresh scan history after feedback
                }
                .onFailure { exception ->
                    _error.value = "Error submitting feedback: ${exception.message}"
                }
        }
    }
}

// Simple data class for UI state
data class ScanResult(
    val scanId: Int,
    val isPhishing: Boolean,
    val riskScore: Double,
    val confidence: String,
    val message: String,
    val predictionTimeMs: Int
)


// ============================================================================
// Usage Example in Activity/Fragment
// ============================================================================

/*
class MainActivity : AppCompatActivity() {
    
    private val viewModel: PhishGuardViewModel by viewModels()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Observe scan result
        lifecycleScope.launch {
            viewModel.scanResult.collect { result ->
                result?.let { displayScanResult(it) }
            }
        }
        
        // Observe loading state
        lifecycleScope.launch {
            viewModel.isLoading.collect { isLoading ->
                progressBar.isVisible = isLoading
            }
        }
        
        // Observe errors
        lifecycleScope.launch {
            viewModel.error.collect { error ->
                error?.let { 
                    Toast.makeText(this@MainActivity, it, Toast.LENGTH_LONG).show()
                }
            }
        }
        
        // Scan button click
        scanButton.setOnClickListener {
            val message = messageEditText.text.toString()
            if (message.isNotBlank()) {
                viewModel.scanMessage(
                    message = message,
                    userId = "user123",
                    deviceId = getDeviceId()
                )
            }
        }
        
        // Load history button
        historyButton.setOnClickListener {
            viewModel.loadScanHistory(userId = "user123")
        }
        
        // Load statistics
        viewModel.loadUserStatistics(userId = "user123")
    }
    
    private fun displayScanResult(result: ScanResult) {
        resultTextView.text = buildString {
            append("Result: ${result.message}\n")
            append("Risk Score: ${String.format("%.2f", result.riskScore)}\n")
            append("Confidence: ${result.confidence}\n")
            append("Prediction Time: ${result.predictionTimeMs}ms")
        }
        
        resultCard.setBackgroundColor(
            if (result.isPhishing) Color.RED else Color.GREEN
        )
    }
    
    private fun getDeviceId(): String {
        return Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ANDROID_ID
        )
    }
}
*/
