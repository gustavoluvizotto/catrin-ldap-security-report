FROM ubuntu:22.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-transport-https \
        apt-utils \
        build-essential \
        ca-certificates \
        curl \
        gcc \
        git \
        gnupg \
        libssl-dev \
        libffi-dev \
        libpcre3-dev \
        nano \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        software-properties-common \
        wget \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /flasksite
WORKDIR /flasksite

RUN mkdir /nginx

# Install GO
RUN rm -rf /usr/local/go \
    && wget https://go.dev/dl/go1.23.6.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.23.6.linux-amd64.tar.gz \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="$PATH:/usr/local/go/bin"

# Install Clickhouse
#RUN curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg \
#    && ARCH=$(dpkg --print-architecture) \
#    && echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] https://packages.clickhouse.com/deb stable main" | tee /etc/apt/sources.list.d/clickhouse.list \
#    && apt-get update \
#    && apt-get install -y --no-install-recommends clickhouse-server clickhouse-client \
#    && apt-get upgrade -y \
#    && rm -rf /var/lib/apt/lists/*

RUN mkdir /venv
RUN python3 -m venv /venv
RUN /venv/bin/python3 -m pip install --upgrade --prefer-binary --compile pip \
    && /venv/bin/python3 -m pip install --upgrade --prefer-binary --compile \
    buildtools \
    setuptools \
    wheel \
    && /venv/bin/python3 -m pip cache purge
ENV PYTHONUNBUFFERED 1

ADD requirements.txt /flasksite/
RUN /venv/bin/python3 -m pip install --prefer-binary --compile -r requirements.txt \
    && /venv/bin/python3 -m pip cache purge

RUN useradd -ms /bin/bash uwsgi
RUN usermod -aG www-data uwsgi
RUN chown uwsgi:www-data -R .

ADD . /flasksite/

RUN mkdir -m ugo+rw /flasksite_dynamic
RUN chown uwsgi:www-data -R /flasksite_dynamic

RUN mkdir /flasksite_data
RUN mkdir -m ugo+rw /flasksite_data/logs
RUN chown uwsgi:www-data -R /flasksite_data

EXPOSE 8080/tcp
VOLUME ["/flasksite", "/flasksite_dynamic", "/flasksite_data"]
ENTRYPOINT ["/bin/sh", "/flasksite/entrypoint.sh"]
