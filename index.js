import axios from "axios";
import express from "express";
import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const API_TIMEOUT_MS = 10000;
const VIRUSTOTAL_RETRY_COUNT = 3;
const VIRUSTOTAL_RETRY_DELAY_MS = 1500;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const emptyViewModel = {
    url: "",
    formError: null,
    overallVerdict: null,
    googleVerdict: null,
    virusTotalVerdict: null
};

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const validateUrl = (value) => {
    const trimmed = typeof value === "string" ? value.trim() : "";

    if (!trimmed) {
        return { error: "Enter a URL to scan." };
    }

    try {
        const parsed = new URL(trimmed);
        if (!["http:", "https:"].includes(parsed.protocol)) {
            return { error: "Only http and https URLs can be scanned.", url: trimmed };
        }

        return { url: parsed.href };
    } catch {
        return { error: "Enter a valid full URL, such as https://example.com.", url: trimmed };
    }
};

const mapProviderError = (providerName, error) => {
    if (error?.code === "ECONNABORTED") {
        return `${providerName} did not respond before the timeout. Try again in a moment.`;
    }

    const status = error?.response?.status;
    if (status === 401 || status === 403) {
        return `${providerName} rejected the API key. Check the configured key.`;
    }

    if (status === 429) {
        return `${providerName} rate limit reached. Try again later.`;
    }

    if (status >= 500) {
        return `${providerName} is temporarily unavailable. Try again later.`;
    }

    return `${providerName} could not complete the scan. Try again later.`;
};

const buildGoogleVerdict = (data, error, url) => {
    if (error) {
        return {
            status: "error",
            message: error
        };
    }

    const matches = Array.isArray(data?.matches) ? data.matches : [];
    if (matches.length > 0) {
        const threatTypes = [...new Set(matches.map((match) => match.threatType))].join(", ");
        return {
            status: "warn",
            message: `Potentially unsafe. Google Safe Browsing reports suspected threats: ${threatTypes}.`,
            matchCount: matches.length,
            advisoryUrl: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(
                url
            )}`
        };
    }

    return {
        status: "ok",
        message: "No threats detected by Google Safe Browsing.",
        matchCount: 0,
        advisoryUrl: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(url)}`
    };
};

const buildVirusTotalVerdict = (data, error) => {
    if (error) {
        return {
            status: "error",
            message: error
        };
    }

    const analysisStatus = data?.data?.attributes?.status;
    if (analysisStatus && analysisStatus !== "completed") {
        return {
            status: "pending",
            message: "VirusTotal is still processing this URL. Try again in a moment."
        };
    }

    const stats = data?.data?.attributes?.stats;
    if (!stats) {
        return {
            status: "pending",
            message: "VirusTotal accepted the URL, but analysis stats are not ready yet."
        };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    if (malicious > 0 || suspicious > 0) {
        return {
            status: "warn",
            message: `Potentially unsafe. ${malicious} malicious and ${suspicious} suspicious detections out of ${total} engines.`,
            stats
        };
    }

    return {
        status: "ok",
        message: `No engines flagged this URL as malicious or suspicious (${total} engines checked).`,
        stats
    };
};

const buildOverallVerdict = (googleVerdict, virusTotalVerdict) => {
    const verdicts = [googleVerdict, virusTotalVerdict].filter(Boolean);

    if (verdicts.some((verdict) => verdict.status === "warn")) {
        return {
            status: "warn",
            message: "One or more providers flagged this URL. Treat it as potentially unsafe."
        };
    }

    if (verdicts.some((verdict) => verdict.status === "pending")) {
        return {
            status: "pending",
            message: "No threats were found yet, but at least one provider is still processing."
        };
    }

    if (verdicts.length > 0 && verdicts.every((verdict) => verdict.status === "error")) {
        return {
            status: "error",
            message: "The scan could not be completed because all providers failed."
        };
    }

    if (verdicts.some((verdict) => verdict.status === "error")) {
        return {
            status: "pending",
            message: "Partial results are available. One provider could not complete the scan."
        };
    }

    return {
        status: "ok",
        message: "No connected provider flagged this URL as malicious or suspicious."
    };
};

const checkGoogleSafeBrowsing = async (url) => {
    if (!process.env.GOOGLE_API_KEY) {
        return buildGoogleVerdict(null, "Google Safe Browsing is not configured. Add GOOGLE_API_KEY.", url);
    }

    try {
        const response = await axios.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            {
                client: {
                    clientId: "url-safety-checker",
                    clientVersion: "1.0"
                },
                threatInfo: {
                    threatTypes: [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url }]
                }
            },
            {
                params: { key: process.env.GOOGLE_API_KEY },
                timeout: API_TIMEOUT_MS
            }
        );

        return buildGoogleVerdict(response.data, null, url);
    } catch (error) {
        console.log("Google API Error:", error.response?.status || error.code || error.message);
        return buildGoogleVerdict(null, mapProviderError("Google Safe Browsing", error), url);
    }
};

const fetchVirusTotalAnalysis = async (analysisId) => {
    for (let attempt = 0; attempt <= VIRUSTOTAL_RETRY_COUNT; attempt += 1) {
        const response = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: {
                "x-apikey": process.env.VIRUSTOTAL_API_KEY
            },
            timeout: API_TIMEOUT_MS
        });

        if (response.data?.data?.attributes?.status === "completed" || attempt === VIRUSTOTAL_RETRY_COUNT) {
            return response.data;
        }

        await wait(VIRUSTOTAL_RETRY_DELAY_MS);
    }

    return null;
};

const checkVirusTotal = async (url) => {
    if (!process.env.VIRUSTOTAL_API_KEY) {
        return buildVirusTotalVerdict(null, "VirusTotal is not configured. Add VIRUSTOTAL_API_KEY.");
    }

    try {
        const submitResponse = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            new URLSearchParams({ url }),
            {
                headers: {
                    "x-apikey": process.env.VIRUSTOTAL_API_KEY,
                    "content-type": "application/x-www-form-urlencoded"
                },
                timeout: API_TIMEOUT_MS
            }
        );

        const analysisId = submitResponse.data?.data?.id;
        if (!analysisId) {
            return buildVirusTotalVerdict(null, "VirusTotal accepted the URL but did not return an analysis id.");
        }

        const analysis = await fetchVirusTotalAnalysis(analysisId);
        return buildVirusTotalVerdict(analysis, null);
    } catch (error) {
        console.log("VirusTotal API Error:", error.response?.status || error.code || error.message);
        return buildVirusTotalVerdict(null, mapProviderError("VirusTotal", error));
    }
};

app.get("/", (req, res) => {
    res.render("index", emptyViewModel);
});

app.get("/healthz", (req, res) => {
    res.status(200).send("ok");
});

app.post("/check-url", async (req, res) => {
    try {
        const validation = validateUrl(req.body.url);
        if (validation.error) {
            return res.status(400).render("index", {
                ...emptyViewModel,
                url: validation.url || "",
                formError: validation.error
            });
        }

        const url = validation.url;
        const [googleVerdict, virusTotalVerdict] = await Promise.all([
            checkGoogleSafeBrowsing(url),
            checkVirusTotal(url)
        ]);

        res.render("index", {
            url,
            formError: null,
            overallVerdict: buildOverallVerdict(googleVerdict, virusTotalVerdict),
            googleVerdict,
            virusTotalVerdict
        });
    } catch (error) {
        console.log("Error:", error.message);
        res.status(500).render("index", {
            ...emptyViewModel,
            overallVerdict: {
                status: "error",
                message: "The scan could not be completed because of an unexpected server error."
            }
        });
    }
});

app.listen(port, "0.0.0.0", () => {
    console.log(`App running on http://localhost:${port}`);
});
