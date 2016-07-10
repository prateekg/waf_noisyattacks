import java.io._

import java.time.LocalDateTime 
// its for the system date and time.
import org.apache.spark.Sparkcontext
// its the entry point to the Apache Spark.
import org.apache.spark.sql._
import org.apache.spark.sql.hive.HiveContext
// these are for the hive Context, which integrates with Hive to access the data stored in Hive.
import org.apache.spark.mllib.clustering.{KMeans, KMeansModel}
// it is used to apply K-Means Clustering over the sample of data
import org.apache.spark.mllib.linalg.Vectors
// converting into Vectors rdd

object NoisyWebAttacks{
	
	val hiveWarehousePath: String = "hdfs:///apps/hive/warehouse/"
	val tableNameMaster1: String = "waf_master_"
	val tableNameMaster2: String = "waf_noisyattack_master_"
	val tableNameOutput1: String = "waf_noisyattack_clusters_"
	val tableNameOutput2: String = "waf_noisyattack_attacks_"
	val tableNameOutput3: String = "waf_noisyattack_anomalousip_"
		

	
	def main(args: Array[String]){
		val sc = new SparkContext()
		val hivecontext = new HiveContext(sc)
		val sqlcontext = new org.apache.spark.sql.SQLContext(sc)

		import hivecontext.implicits._
		import hivecontext.sql4
		// to execute sql queries on hive tables
		
		val now: LocalDateTime = LocalDateTime.now()
		val curr_Day = now.getDayOfMonth().toInt
		val currentMonth = now.getMonthvalue().toInt
		val currentYear = now.getYear().toString
				
		val currentDay: String = {if(curr_Day < 10)
									(0+curr_Day.toString)
		  						else
									(curr_Day.toString)
			}
 		val currentYearMonth: String = {if(currentMonth < 10)
 											(currentYear.toString+0+currentMonth.toString)
										else
											(currentYear.toString+currentMonth.toString)
										}

// C H E C K I N G   F O R   T H E   T  A B L E   N A M E 1 (TO CREATE OUTPUT TABLE IF INPUT EXISTS)
		val currentDayTableName: String = (tableNameMaster1 + currentYearMonth)
		if(sql("SHOW TABLES LIKE '" + currentDayTableName + "'").collect().length == 1){
			println(currentDayTableName + " exists !")
		}else{
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_clusters_"+ currentYearMonth +" (cluster INT, ip_count INT, anomalous_flag STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_attacks_"+ currentYearMonth +" (srcip STRING, attacks STRING, significance STRING, attack_count INT) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_anomalousip_"+ currentYearMonth +" (sourceaddress STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
		}

// C H E C K I N G   F O R   T H E   T A B L E   P A R T I T I O N S   N A M E (TO CREATE OUTPUT TABLE IF INPUT PARTITIONS EXISTS)
		val currentDayPartitionName: String = (tableNameMaster1+ currentYearMonth+ "/day="+ currentDay)
		val partlist = sql("SHOW PARTITIONS " + currentDayTableName) // it will directly return a array()
		val m: String = "[day="+currentDay+"]"
		val temp = for{i <- 1 to partlist.length if m == partlist(i-1).toString} yield 1	
		
		if(temp.toArray.length==1){
			println(currentDayPartitionName + " partition exists.")
		}else{
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_clusters_"+ currentYearMonth +" (cluster INT, ip_count INT, anomalous_flag STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_attacks_"+ currentYearMonth +" (srcip STRING, attacks STRING, significance STRING, attack_count INT) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_anomalousip_"+ currentYearMonth +" (sourceaddress STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
		}

		val wafRawDataAll = sql("SELECT sourceaddress, destinationaddress, customstring3, categorysignificance FROM " + tableNameMaster1 + currentYearMonth + " WHERE (day= '" + currentDay + "' AND categorysignificance = 'Suspicious' or categorysignificance = 'Compromise')")


//--------------------------------------------------------------------------------------------------------------------------
// C H E C K I N G   F O R   T H E   T  A B L E   N A M E 2 (TO CREATE OUTPUT TABLE IF INPUT EXISTS)
	
		val currentDayTableName: String = (tableNameMaster2 + currentYearMonth)
		if(sql("SHOW TABLES LIKE '" + currentDayTableName + "'").collect().length == 1){
			println(currentDayTableName + " exists !")
		}else{
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_clusters_"+ currentYearMonth +" (cluster INT, ip_count INT, anomalous_flag STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_attacks_"+ currentYearMonth +" (srcip STRING, attacks STRING, significance STRING, attack_count INT) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_anomalousip_"+ currentYearMonth +" (sourceaddress STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
		}


// C H E C K I N G   F O R   T H E   T A B L E   P A R T I T I O N S   N A M E (TO CREATE OUTPUT TABLE IF INPUT PARTITIONS EXISTS)
		val currentDayPartitionName: String = (tableNameMaster2+ currentYearMonth+ "/day="+ currentDay)
		val partlist = sql("SHOW PARTITIONS " + currentDayTableName).toArray()
		val m: String = "[day="+currentDay+"]" 
		val temp = for{i <- 1 to partlist.length if m == partlist(i-1).toString} yield 1


		if(temp.toArray.length==1){
			println(currentDayPartitionName + " partition exists.")
		}else{
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_clusters_"+ currentYearMonth +" (cluster INT, ip_count INT, anomalous_flag STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_attacks_"+ currentYearMonth +" (srcip STRING, attacks STRING, significance STRING, attack_count INT) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
			sql("CREATE TABLE IF NOT EXISTS waf_noisyattack_anomalousip_"+ currentYearMonth +" (sourceaddress STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','")
		}


// TEMP 2 is wafSummarizedData
		
		val wafSummarizedData = sql("SELECT srcip ,totalattacks, distinctattacks, compromiseattacks, suspiciousattacks, weightage FROM " + tableNameMaster2 + currentYearMonth + " WHERE (day= '"+ currentDay+"' AND categorysignificance = 'Suspicious' or categorysignificance = 'Compromise')")
		// IT CREATES A sql.dataframe type

//--------------------------------------------------------------------------------------------------------------------------

// TEMP 3 is wafRawGroupedData
		
		wafRawDataAll.registerTempTable("temp1")
		// Registers the wafRawDataAll sql.Dataframe into Hive database as temp1
		val wafRawGroupedData = sql("SELECT sourceaddress, customstring3, categorysignificance, count(customstring3) as attack_count FROM temp1 GROUP BY sourceaddress, customstring3, categorysignificance")
		sql("DROP TABLE temp1")



// TEMP 4 is hrsub1
		
		val temp1 = wafSummarizedData.select(wafSummarizedData("distinctattacks"), wafSummarizedData("compromiseattacks"), wafSummarizedData("suspiciousattacks"), wafSummarizedData("weightage"))


//creating a user defined function
		case class single(l: int, m: int, n: int, o: int)
		val singleudf = udf((a: int, b: int, c: int, d: int) => single(a+" "+b+" "+c+" "+d))
		val temp2 = temp1.withColumn("result", singleudf($"distinctattacks", $"compromiseattacks", $"suspiciousattacks", $"weightage"))
		val temp1 = temp2.select("result")	
		val temp2 = temp1.rdd.map(_.toString)

//ends


// TEMP 5 is wafcat

		val numClusters: Int = 3
		val numIterations: Int = 10

		val hrsub1 = temp2.map(row => Vectors.dense(row.split(' ').map(_.toDouble))).cache()
		var wafcat = KMeans.train(hrsub1, numClusters, numIterations)

		val temp1 = wafSummarizedData.join(wafcat)
		val wafSummarizedData = temp1.select(temp1("srcip") ,temp1("totalattacks"), temp1("distinctattacks"), temp1("compromiseattacks"), temp1("suspiciousattacks"), temp1("weightage"), temp1("cluster"))

		val ipAndClusterNo = wafSummarizedDataFinal.select(wafSummarizedDataFinal("srcip"), wafSummarizedDataFinal("cluster")).withColumnRenamed("srcip", "sourceaddress")

		// ipAndClusterNo is a dataframe with sourceaddress and cluster column
		val temp1 = ipAndClusterNo.groupBy("sourceaddress").count().withColumnRenamed("count", "ip_count")

		// added the ip_count value in temp2 -> sourceaddress, cluster, ip_count 

		val temp2 = temp1.withColumn("anomalous_flag", when($"ip_count" < 10, 'T').otherwise('F'))
		// WILL GO IN THE FIRST OUTPUT TABLE
		val clusterAndIpCount = temp2.select(temp2("cluster"), temp2("ip_count"), temp2("anomalous_flag"))
		val sizeOfCluster =  wafcat.groupBy("cluster").count().withColumnRenamed("count", "size")
		val minSizeOfCluster = temp1.select(temp1("cluster"), temp1("size")).filter(temp1("size")< 10)
		// Selects the "cluster" and "size" column from the registered temporary table and put conditions using filter.


		val temp1 = wafRawGroupedData.join(outlierList, outlierList("sourceaddress") == wafRawGroupedData("sourceaddress"))
		val schema1 = StructType( StructField("sourceaddress", StringType) :: StructField("customstring3", StringType) :: StructField("significance", StringType) :: StructField("attack_count", IntegerType) :: Nil)
		val schema2 = StructType( StructField("sourceaddress", StringType) :: Nil)

 		val outlierIPAttacks = {if(1 <= minSizeOfCluster.count)
									temp1.select(temp1("sourceaddress"), temp1("customstring3"), temp1("categorysignificance"), temp1("attack_count")).withColumnRenamed("categorysignificance", "significance")
								else
									sqlcontext.createDataFrame(sc.emptyRDD[Row], schema1)
								}	
		outlierIPAttacks.registerTempTable("temp")

  		val anomalousIPList = {if(1 <= minSizeOfCluster.count)
									sql("SELECT DISTINCT sourceaddress FROM temp")
								else
									sqlcontext.createDataFrame(sc.emptyRDD[Row], schema2)
								}

        // FIRST OUTPUT TABLE
  		clusterAndIpCount.registerTempTable("temp")
  		sql("INSERT INTO waf_noisyattack_clusters_"+ currentYearMonth +" PARTITION (day = '"+currentDay+"') SELECT * from temp")
  		sql("DROP TABLE temp")

  		// SECOND OUTPUT TABLE
  		outlierIPAttacks.registerTempTable("temp")
  		sql("INSERT INTO waf_noisyattack_attacks_"+ currentYearMonth +" PARTITION (day = '"+currentDay+"') SELECT * from temp")
  		sql("DROP TABLE temp")

  		// SECOND OUTPUT TABLE
  		anomalousIPList.registerTempTable("temp")
  		sql("INSERT INTO waf_noisyattack_anomalousip_"+ currentYearMonth +" PARTITION (day = '"+currentDay+"') SELECT * from temp")
  		sql("DROP TABLE temp")

  		println("O U T P U T   T A B L E S   G E N E R A T E D   ! ! !")
  		println("\n\n")

	}
}