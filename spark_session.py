__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

from time import time
import os

from pyspark import SparkConf
from pyspark.sql import SparkSession


def get_spark_instance():
    os.environ["SPARK_LOCAL_IP"] = "127.0.0.1"

    APP_NAME = "NIP"

    spark_conf = SparkConf().setAppName(f"pyspark-{APP_NAME}-{int(time())}").set(
        "spark.submit.deployMode", "client"
    ).set("spark.sql.parquet.binaryAsString", "true"
    ).set("spark.driver.bindAddress", "localhost"
    ).set("spark.driver.host", "127.0.0.1"
    ).set("spark.driver.port", "0"
    ).set("spark.executor.instances", "1"
    ).set("spark.executor.cores", "40"
    ).set("spark.executor.memory", "100G"
    ).set("spark.executor.memoryOverhead", "8G"
    ).set("spark.driver.cores", "12"
    ).set("spark.driver.memory", "20G"
    )

    print("SparkConf created")
    spark = SparkSession.builder.config(conf=spark_conf).getOrCreate()
    sc = spark.sparkContext
    sc.setCheckpointDir("./checkpoint")
    print("Started SparkSession")
    print(f"Spark version {sc.version}")
    return spark, sc


def clean_spark(spark, sc):
    spark.catalog.clearCache()
    sc.stop()
    print("spark cleaned up")
