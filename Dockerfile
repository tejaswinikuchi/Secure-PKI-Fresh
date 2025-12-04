###############################
# Stage 1: Builder
###############################
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy dependency list
COPY requirements.txt .

# Install dependencies into /install directory
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt



###############################
# Stage 2: Runtime
###############################
FROM python:3.11-slim

ENV TZ=UTC
WORKDIR /app

# Install cron + timezone
RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata && \
    ln -sf /usr/share/zoneinfo/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app.py /app/app.py
COPY api.py /app/api.py
COPY student_private.pem /app/student_private.pem
COPY student_public.pem /app/student_public.pem
COPY instructor_public.pem /app/instructor_public.pem


# ---------------------------------------------------------
# STEP 8 DOES NOT REQUIRE REAL CRON JOBS YET
# Create an empty cron file so cron service works
# ---------------------------------------------------------
RUN echo "" > /etc/cron.d/seed_cron && \
    chmod 0644 /etc/cron.d/seed_cron && \
    crontab /etc/cron.d/seed_cron


# Create volume mount points
RUN mkdir -p /data && mkdir -p /cron && \
    chmod 755 /data && chmod 755 /cron

VOLUME ["/data", "/cron"]

# Expose port
EXPOSE 8080

# Start cron + API server
CMD cron && python -m uvicorn api:app --host 0.0.0.0 --port 8080
