"""AWS Bedrock Knowledge Bases: a custom transformation Lambda at POST_CHUNKING.

Bedrock writes each batch of chunks to S3 and calls this function with the location; the function
checks every chunk with the guardrail service, drops the ones to remove or hold, masks the ones to
redact, adds the guard's decision to the chunk metadata, writes the batch back, and returns where.

Configure the knowledge base's data source with a custom transformation:
    stepToApply: POST_CHUNKING, transformationFunction: this Lambda, intermediateStorage: an S3 bucket

Environment: GUARDRAIL_URL, GUARDRAIL_CLIENT_KEY (store it in Secrets Manager in production).
The event and batch file shapes follow the Bedrock "custom transformation" contract; check them
against the current AWS documentation before deploying.
"""

from __future__ import annotations

import json
import os
import urllib.request

import boto3  # provided by the Lambda runtime

s3 = boto3.client("s3")
URL = os.environ["GUARDRAIL_URL"].rstrip("/")
KEY = os.environ.get("GUARDRAIL_CLIENT_KEY", "")


def check(chunks: list[dict]) -> list[dict]:
    req = urllib.request.Request(
        f"{URL}/v1/ingest",
        data=json.dumps({"documents": chunks}).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {KEY}"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())["results"]


def handler(event, context):
    bucket = event["bucketName"]
    out_files = []
    for input_file in event.get("inputFiles", []):
        out_batches = []
        for batch in input_file.get("contentBatches", []):
            key = batch["key"]
            body = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
            contents = body.get("fileContents", [])
            items = [{"text": c.get("contentBody", ""), "chunk_id": f"{key}#{i}",
                      "source": (c.get("contentMetadata") or {}).get("x-amz-bedrock-kb-source-uri")}
                     for i, c in enumerate(contents)]
            kept = []
            for content, result in zip(contents, check(items) if items else []):
                if not result["usable"]:
                    continue  # removed, or held for review: the review webhook can re-ingest it later
                content["contentBody"] = result["content"]
                meta = content.setdefault("contentMetadata", {})
                meta["guard_decision"] = result["decision"]
                meta["guard_policy"] = result["metadata"].get("guard_policy", "")
                kept.append(content)
            out_key = key.replace("/input/", "/output/", 1) if "/input/" in key else f"guarded/{key}"
            s3.put_object(Bucket=bucket, Key=out_key, Body=json.dumps({"fileContents": kept}).encode())
            out_batches.append({"key": out_key})
        out_files.append({
            "originalFileLocation": input_file.get("originalFileLocation"),
            "fileMetadata": input_file.get("fileMetadata", {}),
            "contentBatches": out_batches,
        })
    return {"outputFiles": out_files}
