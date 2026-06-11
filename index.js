import axios from "axios";
import express from "express";
import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Middleware
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

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
        advisoryUrl: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(
            url
        )}`
    };
};

const buildVirusTotalVerdict = (data, error) => {
    if (error) {
        return {
            status: "error",
            message: error
        };
    }

    const stats = data?.data?.attributes?.stats;
    if (!stats) {
        return {
            status: "error",
            message: "VirusTotal response missing analysis stats."
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

// Routes
app.get("/", (req, res) => {
    res.render("index", { url: null, googleVerdict: null, virusTotalVerdict: null });
});

app.get("/healthz", (req, res) => {
    res.status(200).send("ok");
});

app.post("/check-url", async (req, res) => {
    try {
        const url = req.body.url;
        
        // Google Safe Browsing API
        let googleResult = null;
        let googleError = null;
        try {
            const googleResponse = await axios.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                {
                    client: {
                        clientId: "yourapp",
                        clientVersion: "1.0"
                    },
                    threatInfo: {
                        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url: url }]
                    }
                },
                {
                    params: { key: process.env.GOOGLE_API_KEY }
                }
            );
            googleResult = googleResponse.data;
        } catch (error) {
            console.log("Google API Error:", error.response?.data || error.message);
            googleError = error.response?.data?.error?.message || "Google API Error";
        }

        // VirusTotal API (submit URL, then fetch analysis)
        let virusTotalResult = null;
        let virusTotalError = null;
        try {
            const submitResponse = await axios.post(
                "https://www.virustotal.com/api/v3/urls",
                new URLSearchParams({ url }),
                {
                    headers: {
                        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
                        "content-type": "application/x-www-form-urlencoded"
                    }
                }
            );

            const analysisId = submitResponse.data?.data?.id;
            if (!analysisId) {
                throw new Error("VirusTotal submission did not return an analysis id");
            }

            const analysisResponse = await axios.get(
                `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
                {
                    headers: {
                        "x-apikey": process.env.VIRUSTOTAL_API_KEY
                    }
                }
            );
            virusTotalResult = analysisResponse.data;
        } catch (error) {
            console.log("VirusTotal API Error:", error.response?.data || error.message);
            virusTotalError = error.response?.data?.error?.message || "VirusTotal API Error";
        }

        const googleVerdict = buildGoogleVerdict(googleResult, googleError, url);
        const virusTotalVerdict = buildVirusTotalVerdict(virusTotalResult, virusTotalError);

        res.render("index", { 
            url,
            googleVerdict,
            virusTotalVerdict
        });
    } catch (error) {
        console.log("Error:", error);
        res.status(500).render("index", { 
            url: null,
            googleVerdict: { status: "error", message: error.message },
            virusTotalVerdict: { status: "error", message: error.message }
        });
    }
});

// Start server
app.listen(port, "0.0.0.0", () => {
    console.log(`App running on http://localhost:${port}`);
});
