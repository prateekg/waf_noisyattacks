Sys.setenv(HIVE_HOME="/usr/hdp/2.2.8.0-3150/hive")
Sys.setenv(HADOOP_HOME="/usr/hdp/2.2.8.0-3150/hadoop")

library(rJava)
library(logging)

basicConfig() #bootstarpping the loggers

addHandler(writeToFile, logger="Logs", file="/home/prateek/Downloads/waf_noisyattackdetection/waf_noisyattackdetection.log") #intialise the handler to logger=logs and storing it in the file

#LOGINFO displays the message to the logger
loginfo("############### Initialization of Rscript ###############", logger="Logs")
loginfo("Loading libraries", logger="Logs")
library(RHive)
library(plyr)
library(dplyr)
library(lubridate)
library(data.table)
loginfo("Libraries are loaded!", logger="Logs")


#SETTING WORKING DIRECTORY`1                                                                `
loginfo("Setting working directory", logger="Logs") 
workingDirPath <- "/data/analytic_models/working_dir/waf_noisyattackdetection"
dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
setwd(workingDirPath)
loginfo("Working Directory is set", logger="Logs")


#CREATING LOG FILES
loginfo("Creating log file", logger="Logs")
logDirPath <- "/d123ata/analytic_models/logs/waf_noisyattackdetection"
dir.create(logDirPath, showWarnings=FALSE, recursive=TRUE)
Sys.chmod(logDirPath, mode = "0777", use_umask = FALSE)
con <- file("/data/analytic_models/logs/waf_noisyattackdetection/waf_noisyattackdetection_stdout.log")
sink(con, append=TRUE)
sink(con, append=TRUE, type="message")
loginfo("Log file is created", logger="Logs")


#SETTING GLOBAL VARIABLES
loginfo("Setting global variables", logger="Logs")
rhive.init() # procedure that initialises internally, if hadoop_home and hive_home are not set, it will display the error !
options(warn = -1)
outlierList <- list()
rWorkingDir <- getwd() #it returns an absolute fielpath which is the current working directory of the R process (setwd(dir): set the working directory to 'dir')
hiveWarehousePath <- "hdfs:///apps/hive/warehouse/"
tableNameMaster1 <- "/waf_master_"
tableNameMaster2 <- "/waf_noisyattack_master_"
tableNameOutput1 <- "/waf_noisyattack_clusters_"
tableNameOutput2 <- "/waf_noisyattack_attacks_"
tableNameOutput3 <- "/waf_noisyattack_anomalousip_"
partFileNamePattern <- "part-*-*"
loginfo("Global variables are set!", logger="Logs")



#Clening up the working directory if any files exists in directory
filesInDir <- list.files(rWorkingDir, pattern = partFileNamePattern) 
# produces a character vector of the names of the files or directory in the named directory.
# rWorkingDir -> character vector of the full path names
# pattern -> only file names which match the pattern expression will be returned
if (0 < length(filesInDir)){
  loginfo("Cleaning Working Directory", logger="Logs")
  unlink(workingDirPath, recursive = TRUE) 
  # unlink deletes the file or directory specified by workingDirPath
  # recursive = (should directories be deleted recursively ?) : if 'false'; directories are not deleted, not even empty ones !!....so TRUE
 
  # the below two lines are used as a one funtion i.e dir.create()
  dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
  # dir.create() creates the last element of the path, unless recursive=TRUE
  #showWarnings : should the warnings and errors be shown ?
  Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
  # Sys.chmod sets the file permission of one or more files 
  # use_umask : should the mode be restricted with the umask settings ?
  # dir.create will show failure if the directory already exists. If showWarnings = TRUE, it will give warning for an unexpected failure
  loginfo("Working directory is cleaned", logger="Logs")
}
rm(filesInDir)
# removes the files in filesInDir



loginfo("Loading %s function!", "createTable", logger="Logs")

# we are just creating a funtion named "createTable" 
createTable <- function() {
  loginfo("Conneting to Hive server IP = %s and port = %s", "<Hive_Server_Address>", "10000", logger="Logs")
  
  rhive.connect(host = "<Hive_Server_Address>", port = 10000, hiveServer2 = TRUE)
  # rhive.connect connects to the hive server, it is necessary to connect to hive before using any hive function otherwise it will show the malfunction error
  
  # QUERY CONTAINS CLUSTERS
  loginfo("Conneted to Hive server!", logger="Logs")
  queryPart1 <- "CREATE TABLE IF NOT EXISTS waf_noisyattack_clusters_"
  queryPart2 <- " (cluster INT, ip_count INT, anomalous_flag STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','"
  query <- paste0(queryPart1, currentYearMonth, queryPart2)
  # paste0 concatenate the vectors after converting them to character

  loginfo("Creating table waf_noisyattack_clusters_%s", currentYearMonth, logger="Logs")
  status <- rhive.execute(query)
  # rhive.execute() executes the Hive Query "query" which is in Hive Query Language. It returns TRUE on success

  if(status == FALSE){
    return (FALSE)
  }
  rm(queryPart1, queryPart2, query, status)


  # QUERY CONTAINS ATTACKS
  loginfo("Created table waf_noisyattack_clusters_%s", currentYearMonth, logger="Logs")
  queryPart1 <- "CREATE TABLE IF NOT EXISTS waf_noisyattack_attacks_"
  queryPart2 <- " (srcip STRING, attacks STRING, significance STRING, attack_count INT) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','"
  query <- paste0(queryPart1, currentYearMonth, queryPart2)
  loginfo("Creating table waf_noisyattack_attacks_%s", currentYearMonth, logger="Logs")
  
  status <- rhive.execute(query)
  if(status == FALSE){
    return (FALSE)
  }
  rm(queryPart1, queryPart2, query, status)
  
  
  # QUERY CONTAINS ANOMALOUSIP
  loginfo("Created table waf_noisyattack_attacks_%s", currentYearMonth, logger="Logs")
  queryPart1 <- "CREATE TABLE IF NOT EXISTS waf_noisyattack_anomalousip_"
  queryPart2 <- " (sourceaddress STRING) PARTITIONED BY (day INT) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','"
  query <- paste0(queryPart1, currentYearMonth, queryPart2)
  loginfo("Creating table waf_noisyattack_anomalousip_%s", currentYearMonth, logger="Logs")
  status <- rhive.execute(query)
  if(status == FALSE){
    return (FALSE)
  }
  rm(queryPart1, queryPart2, query, status)
  loginfo("Created table waf_noisyattack_anomalousip_%s", currentYearMonth, logger="Logs")
  return(TRUE)
}
#FUNCTION ENDS
loginfo("%s function is loaded!", "createTable", logger="Logs")

# CREATING THE currentValueMonth
loginfo("Calculating datetime values", logger="Logs")
#these will go as it is in scala
currentDay <- as.numeric(day(Sys.Date()))
currentMonth <- as.numeric(month(Sys.Date()))
currentYear <- as.numeric(year(Sys.Date()))
if(currentDay < 10) {
  currentDay <- as.character(currentDay)
  currentDay <- paste0(0,currentDay)
}
if(currentMonth < 10) {
  currentYearMonth <- as.numeric(paste0(currentYear,0,currentMonth))
} else {
  currentYearMonth <- as.numeric(paste0(currentYear,currentMonth))
}
# We finally get the value of currentYearMonth


loginfo("Conneting to Hive server IP = %s and port = %s", "<Hive_Server_Address>", "10000", logger="Logs")
rhive.connect(host = "<Hive_Server_Address>", port = 10000, hiveServer2 = TRUE)
loginfo("Connected to Hive server!", logger="Logs")

loginfo("Checking waf_master_%s table exist or not!", currentYearMonth, logger="Logs")
currentDayTableExists <- paste0(hiveWarehousePath, tableNameMaster1, currentYearMonth)
currentDayTableCheck <- rhive.hdfs.exists(currentDayTableExists)
# rhive.hdfs.exists() check whether the file or directory specified by path (i.e currentDayTableExists) is or not ?
loginfo("waf_master_%s table is exist = %s", currentYearMonth, currentDayTableCheck, logger="Logs")

if(currentDayTableCheck == FALSE)
{
  status <- createTable()
  if (status == FALSE){
    status <- rhive.close()
    loginfo("Could not able to create table!", logger="Logs")
    rm(list = ls())
	stop("Exiting from script!")
  }
  status <- rhive.close()
  loginfo("Could not found the input table waf_master_%s", currentYearMonth, logger="Logs")
  rm(list = ls())
  stop("Exiting from script!")
}

loginfo("Checking partition exists in table waf_master_%s or not!", currentYearMonth, logger="Logs")
currentDayPartitionExists <- paste0(hiveWarehousePath, tableNameMaster1, currentYearMonth, "/day=", currentDay)
currentDayPartitionCheck <- rhive.hdfs.exists(currentDayPartitionExists)
loginfo("partition is exist in table waf_master_%s = %s", currentYearMonth, currentDayPartitionCheck, logger="Logs")
if(currentDayPartitionCheck == FALSE)
{
  status <- createTable()
  if (status == FALSE){
    status <- rhive.close()
    loginfo("Could not able to create table!", logger="Logs")
    rm(list = ls())
    stop("Exiting from script!")
 }
  status <- rhive.close()
  loginfo("Partition day = %s is not present in table waf_master_%s", currentYearMonth, logger="Logs")
  rm(list = ls())
  stop("Exiting from script!")
}

loginfo("Checking for part files to import into working directory", logger="Logs")
partFileshdfsPath <- paste0(hiveWarehousePath, tableNameMaster1, currentYearMonth, "/day=", currentDay)

loginfo("Generating paths of all available part files under partition", logger="Logs")
partFilesPaths <- as.character(rhive.hdfs.ls(partFileshdfsPath)$file)
if(0 < length(partFilesPaths)) {
	loginfo("%d part files are available under partition", length(partFilesPaths), logger="Logs")

 for(i in 1:length(partFilesPaths)) {
	result <- rhive.hdfs.get(partFilesPaths[i], rWorkingDir)
 }

}
loginfo("files are copied to working directory", logger="Logs")


#LOADING PARTDATA
loginfo("Loading %s function!", "loadPartData", logger="Logs")
colClassess= ("sourceaddress", "destinationaddress", "customstring3", "categorysignificance") 
loadPartData <- function(files) { 
  dataFrames <- lapply(files, function(x) read.csv(x, header = FALSE, sep = ",", stringsAsFactors = FALSE, fill = TRUE, quote = "", colClasses=c("character", "character", "character", "character")))
  # Applies a function to elements in a list or a vector and returns the results in a list
  return(dplyr::bind_rows(dataFrames))
}
loginfo("Loaded %s function!", "loadPartData", logger="Logs")


#LOADING PARTDATA2
loginfo("Loading %s function!", "loadPartData2", logger="Logs")
colClasses= ("srcip", "totalattacks", "distinctattacks", "compromiseattacks", "suspiciousattacks", "weightage")
loadPartData2 <- function(files) { 
  dataFrames <- lapply(files, function(x) read.csv(x, header = FALSE, sep = ",", stringsAsFactors = FALSE, fill = TRUE, quote = "", colClasses=c("character", "numeric", "numeric", "numeric", "numeric", "numeric")))
  return(dplyr::bind_rows(dataFrames))
}
loginfo("Loaded %s function!", "loadPartData2", logger="Logs")

loginfo("Importing the data from part files", logger="Logs")
partFilesNames <- list.files(rWorkingDir, pattern = partFileNamePattern)
loginfo("Removing zero size file(s)", logger="Logs")
newpartFilesNames <- ""

k <- 1
for(z in 1:length(partFilesNames)){
  tempFileName <- file.info(partFilesNames[z])$size
  if(0 == as.integer(tempFileName)) {
    next
  } else {
    newpartFilesNames[k] <- partFilesNames[z]
	k <- k + 1 
  }
}

if(0 == length(newpartFilesNames)) {
	status <- createTable()
	if (status == FALSE){
		status <- rhive.close()
		loginfo("Could not able to create table", logger="Logs")
		rm(list = ls())
		stop("Exiting from script!")
	}
	loginfo("Removing part files from working directory", logger="Logs")
	if (file.exists(partFilesNames)){
	  unlink(workingDirPath, recursive = TRUE)
	  loginfo("Removed part files from working directory", logger="Logs")
	}
	dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
	Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
	status <- rhive.close()
	loginfo("All zero size files are present in table waf_master_%s", currentYearMonth, logger="Logs")
	rm(list = ls())
	stop("No data to process!")
}
loginfo("Removed zero size file(s)", logger="Logs")
wafRawDataAll <- data.frame(loadPartData(newpartFilesNames))
loginfo("Imported the data from part files!", logger="Logs")
rm(z, k, tempFileName, newpartFilesNames)
if(0 == nrow(wafRawDataAll)){
  status <- createTable()
  if (status == FALSE){
    loginfo("Could not able to create table!", logger="Logs")
	loginfo("Removing part files from working directory", logger="Logs")
	if (file.exists(partFilesNames)){
		unlink(workingDirPath, recursive = TRUE)
		loginfo("Removed part files from working directory", logger="Logs")
	}
	dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
	Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
	setwd(workingDirPath)
	status <- rhive.close()
    rm(list = ls())
    stop("Exiting from script!")
  }
  loginfo("No data to process!", logger="Logs")
  loginfo("Removing part files from working directory", logger="Logs")
  if (file.exists(partFilesNames)){
	unlink(workingDirPath, recursive = TRUE)
	loginfo("Removed part files from working directory", logger="Logs")
  }
  dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
  Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
  setwd(workingDirPath)
  rm(list = ls())
  stop("Exiting from script!")
}
names(wafRawDataAll) <- c("sourceaddress", "destinationaddress", "customstring3", "categorysignificance")
loginfo("%d rows fetched successfully imported from csv file before filter", nrow(wafRawDataAll), logger="Logs")

wafRawDataAll$categorysignificance[wafRawDataAll$categorysignificance == ""] <- "Suspicious"
wafRawDataAll <- wafRawDataAll %>% filter(categorysignificance == "Suspicious" | categorysignificance == "Compromise")
if(0 == nrow(wafRawDataAll)) {
  status <- createTable()
  if (status == FALSE){
    loginfo("Could not able to create table!", logger="Logs")
	loginfo("Removing part files from working directory", logger="Logs")
	if (file.exists(partFilesNames)){
		unlink(workingDirPath, recursive = TRUE)
		loginfo("Removed part files from working directory", logger="Logs")
	}
	dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
	Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
	setwd(workingDirPath)
	status <- rhive.close()
    rm(list = ls())
    stop("Exiting from script!")
  }
  loginfo("No suspicious and compromise type data to process!", logger="Logs")
  loginfo("Removing part files from working directory", logger="Logs")
  if (file.exists(partFilesNames)){
	unlink(workingDirPath, recursive = TRUE)
	loginfo("Removed part files from working directory", logger="Logs")
  }
  dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
  Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
  setwd(workingDirPath)
  rm(list = ls())
  stop("Exiting from script!")
} 
wafRawDataAll <- select(wafRawDataAll, sourceaddress, customstring3, categorysignificance)
loginfo("%d rows fetched successfully imported from csv file", nrow(wafRawDataAll), logger="Logs")

loginfo("Removing part files from working directory", logger="Logs")
if (file.exists(partFilesNames)){
  unlink(workingDirPath, recursive = TRUE)
  loginfo("Removed part files from working directory", logger="Logs")
}
dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
setwd(workingDirPath)
rWorkingDir <- getwd()
status <- rhive.close()
rm(status, currentYear, currentMonth, currentDayTableCheck, currentDayPartitionCheck, currentDayTableExists, currentDayPartitionExists, partFilesNames, partFilesPaths, partFileshdfsPath)

# TILL NOW WE ARE TAKING THE DATA VALUE IN wafrawdataAll WHOSE CATEGORY SIGNIFICANCE IS "COMPROMISE" OR "SUSPICIOUS". 

loginfo("Conneting to Hive server IP = %s and port = %s", "<Hive_Server_Address>", "10000", logger="Logs")
rhive.connect(host = "<Hive_Server_Address>", port = 10000, hiveServer2 = TRUE)
loginfo("Conneted to Hive server!", logger="Logs")

loginfo("Checking waf_noisyattack_master_%s table is exist or not!", currentYearMonth, logger="Logs")
currentDayTableExists <- paste0(hiveWarehousePath, tableNameMaster2, currentYearMonth)
currentDayTableCheck <- rhive.hdfs.exists(currentDayTableExists)
loginfo("waf_noisyattack_master_%s table is exist = %s", currentYearMonth, currentDayTableCheck, logger="Logs")
if(currentDayTableCheck == FALSE)
{
  status <- createTable()
  if (status == FALSE){
    status <- rhive.close()
    loginfo("Could not able to create table!", logger="Logs")
    rm(list = ls())
    stop("Exiting from script!")
  }
  status <- rhive.close()
  loginfo("Could not found the input table waf_noisyattack_master_%s", currentYearMonth, logger="Logs")
  rm(list = ls())
  stop("Exiting from script!")
}

loginfo("Checking partition is exist in table waf_noisyattack_master_%s or not!", currentYearMonth, logger="Logs")
currentDayPartitionExists <- paste0(hiveWarehousePath, tableNameMaster2, currentYearMonth, "/day=", currentDay)
currentDayPartitionCheck <- rhive.hdfs.exists(currentDayPartitionExists)
loginfo("partition is exist in table waf_noisyattack_master_%s = %s", currentYearMonth, currentDayPartitionCheck, logger="Logs")
if(currentDayPartitionCheck == FALSE)
{
  status <- createTable()
  if (status == FALSE){
    status <- rhive.close()
    loginfo("Could not able to create table!", logger="Logs")
    rm(list = ls())
    stop("Exiting from script!")
  }
  status <- rhive.close()
  loginfo("Partition is not present in table waf_noisyattack_master_%s", currentYearMonth, logger="Logs")
  rm(list = ls())
  stop("Exiting from script!")
}

loginfo("Checking for part files to import into working directory", logger="Logs")
partFileshdfsPath <- paste0(hiveWarehousePath, tableNameMaster2, currentYearMonth, "/day=", currentDay)
loginfo("Generating paths of all available part files under partition day = %s", currentDay, logger="Logs")
partFilesPaths <- as.character(rhive.hdfs.ls(partFileshdfsPath)$file)
if(0 < length(partFilesPaths)) {
	loginfo("%d part files are available under partition day = %s", length(partFilesPaths), currentDay, logger="Logs")
 for(i in 1:length(partFilesPaths)) {
	result <- rhive.hdfs.get(partFilesPaths[i], rWorkingDir)
 }
}
loginfo("files are copied to working directory", logger="Logs")

loginfo("Importing the data from part files", logger="Logs")
partFilesNames <- list.files(rWorkingDir, pattern = partFileNamePattern)
loginfo("Removing zero size file(s)", logger="Logs")
k <- 1
newpartFilesNames <- ""
for(z in 1:length(partFilesNames)){
  tempFileName <- file.info(partFilesNames[z])$size
  if(0 == as.integer(tempFileName)) {
    next
  } else {
    newpartFilesNames[k] <- partFilesNames[z]
	k <- k + 1
  }
}
if(0 == length(newpartFilesNames)) {
	status <- createTable()
	if (status == FALSE){
		status <- rhive.close()
		loginfo("Could not able to create table", logger="Logs")
		rm(list = ls())
		stop("Exiting from script!")
	}
	status <- rhive.close()
	loginfo("All zero size files are present in table waf_noisyattack_master_%s", currentYearMonth, logger="Logs")
	rm(list = ls())
	stop("No data to process!")
}
loginfo("Removed zero size file(s)", logger="Logs")
wafSummarizedData <- data.frame(loadPartData2(newpartFilesNames))
loginfo("Imported the data from part files!", logger="Logs")
if (0  == nrow(wafSummarizedData)) {
  status <- createTable()
  if (status == FALSE){
    loginfo("Could not able to create table!", logger="Logs")
	loginfo("Removing part files from working directory", logger="Logs")
	if (file.exists(partFilesNames)){
		unlink(workingDirPath, recursive = TRUE)
		loginfo("Removed part files from working directory", logger="Logs")
	}
	dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
	Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
	setwd(workingDirPath)
	status <- rhive.close()
    rm(list = ls())
    stop("Exiting from script!")
  }
  loginfo("No data to process!", logger="Logs")
  loginfo("Removing part files from working directory", logger="Logs")
  if (file.exists(partFilesNames)){
	unlink(workingDirPath, recursive = TRUE)
	loginfo("Removed part files from working directory", logger="Logs")
  }
  dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
  Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
  setwd(workingDirPath)
  status <- rhive.close()
  rm(list = ls())
  stop("Exiting from script!")
}
names(wafSummarizedData) <- c("srcip", "totalattacks", "distinctattacks", "compromiseattacks", "suspiciousattacks", "weightage")
loginfo("%d rows fetched successfully imported from part files", nrow(wafSummarizedData), logger="Logs")

loginfo("Removing part files from working directory", logger="Logs")
if (file.exists(partFilesNames)){
  unlink(workingDirPath, recursive = TRUE)
  loginfo("Removed part files from working directory", logger="Logs")
}
dir.create(workingDirPath, showWarnings=FALSE, recursive=TRUE)
Sys.chmod(workingDirPath, mode = "0777", use_umask = FALSE)
setwd(workingDirPath)
rWorkingDir <- getwd()
status <- rhive.close()
rm(status, currentDayTableCheck, currentDayPartitionCheck, currentDayTableExists, currentDayPartitionExists, partFilesNames, partFilesPaths, partFileshdfsPath, partFileNamePattern)

loginfo("calculation of attack count", logger="Logs")
wafRawGroupedData <- ddply(wafRawDataAll, c("sourceaddress", "customstring3", "categorysignificance"), function(x){
  count <- as.numeric(length(x$customstring3))
  data.frame(attack_count = count)
})
rm(wafRawDataAll)
loginfo("calculated attack count!", logger="Logs")



loginfo("Computing cluster values", logger="Logs")
hrsub1 <- select(wafSummarizedData, distinctattacks, compromiseattacks, suspiciousattacks, weightage)
tryCatch(wafcat <- kmeans(hrsub1, centers=3, nstart=10), 
	error = function(e) loginfo("Could not able to formed the anomalous cluster due to inproper input data", logger="Logs"))
wafSummarizedData$cluster <- wafcat$cluster
sizeOfClusterVector <- as.vector(wafcat$size)
minSizeOfClusterVector <- as.vector(which(sizeOfClusterVector < 10), mode = "numeric")
minSizeOfClusterVector
ipAndClusterNo <- select(wafSummarizedData, srcip, cluster)
rm(wafSummarizedData, wafcat, hrsub1)
names(ipAndClusterNo) <- c("sourceaddress", "cluster")
loginfo("Computed cluster values!", logger="Logs")



loginfo("Trying to find anomalous cluster", logger="Logs")
clusterAndIPCount <- ddply(ipAndClusterNo, "cluster", function(x){
  count <- as.numeric(length(x$sourceaddress))
  if(count < 10){
    data.frame(ip_count = count, anomalous_flag = 'T')
  } else {
    data.frame(ip_count = count, anomalous_flag = 'F')
  }
})
rownames(clusterAndIPCount) <- NULL
colnames(clusterAndIPCount) <- c("cluster", "ip_count", "anomalous_flag")
loginfo("Tried to find anomalous cluster", logger="Logs")

if(1 <= length(minSizeOfClusterVector)) {
  loginfo("anomalous cluster found!", logger="Logs")
  
  loginfo("Generating attack details of anomalous cluster(s)", logger="Logs")
  for(i in 1:length(minSizeOfClusterVector)) {
    outlierList[i] <- list(filter(ipAndClusterNo, ipAndClusterNo$cluster == minSizeOfClusterVector[i]))
  }
  outlierIPs <- do.call(rbind,outlierList)
  outlierIPAttacks <- merge(outlierIPs, wafRawGroupedData, by.x="sourceaddress", by.y="sourceaddress", all.x = TRUE)
  rm(outlierIPs, wafRawGroupedData, outlierList, minSizeOfClusterVector)
  outlierIPAttacks <- select(outlierIPAttacks, sourceaddress, customstring3, categorysignificance, attack_count)
  rownames(outlierIPAttacks) <- NULL
  colnames(outlierIPAttacks) <- c("sourceaddress", "attacks", "significance", "attack_count")
  loginfo("Genereted attack details", logger="Logs")
  


  loginfo("Generating anomalous ip list", logger="Logs")  
  anomalousIPList <- unique(select(outlierIPAttacks, sourceaddress))
  loginfo("Genereted anomalous ip list", logger="Logs")
} else {
  loginfo("No anomalous cluster found!", logger="Logs")
  outlierIPAttacks <- data.frame(sourceaddress = character(0), attacks = character(0), significance = character(0), attack_count = numeric(0)) 
  outlierIPAttacks <- data.frame(sourceaddress = "NULL", attacks = "NULL", significance = "NULL", attack_count =  "NULL")
  loginfo("Could not genereted the attack details of anomalous cluster", logger="Logs")
  
  anomalousIPList <- data.frame(sourceaddress = character(0)) 
  anomalousIPList <- data.frame(sourceaddress = "NULL")
  loginfo("Could not genereted the anomalous ip list", logger="Logs")
}


loginfo("Calling %s function", "createTable", logger="Logs")        
status <- createTable()
loginfo("Returning from %s function", "createTable", logger="Logs")
if (status == FALSE){
  status <- rhive.close()
  loginfo("Could not able to create table!", logger="Logs")
  rm(list = ls())
  stop("Exiting from script!")
}

loginfo("Flushing data to table waf_noisyattack_clusters_%s", currentYearMonth, logger="Logs")
waf_noisyattack_hdfspath <- paste0(hiveWarehousePath, tableNameOutput1, currentYearMonth)

loginfo("Giving all read and write permissions to path = %s", waf_noisyattack_hdfspath, logger="Logs")
d <- rhive.hdfs.chmod("777", waf_noisyattack_hdfspath, recursive=TRUE)

loginfo("all read and write permissions are given", logger="Logs")
waf_noisyattack_hdfspath <- paste0(hiveWarehousePath, tableNameOutput1, currentYearMonth, "/day=", currentDay)

loginfo("Creating partition at %s", waf_noisyattack_hdfspath, logger="Logs")
partitions <- rhive.hdfs.mkdirs(waf_noisyattack_hdfspath)

loginfo("Created partition!", logger="Logs")
waf_noisyattack_localpath <- paste0(rWorkingDir, "/waf_noisyattack_clusters.csv")

loginfo("Creating waf_noisyattack_clusters.csv file at path %s", waf_noisyattack_localpath, logger="Logs")
d <- write.table(clusterAndIPCount, file = waf_noisyattack_localpath, quote = FALSE, row.names=FALSE, sep = ",", col.names = FALSE)

loginfo("Created waf_noisyattack_clusters.csv file", logger="Logs")
loginfo("Copying waf_noisyattack_clusters.csv file data from local %s to hdfs %s", waf_noisyattack_localpath, waf_noisyattack_hdfspath, logger="Logs")
d <- rhive.hdfs.put(waf_noisyattack_localpath, waf_noisyattack_hdfspath, srcDel = TRUE, overwrite = TRUE)

loginfo("Copied the waf_noisyattack_clusters.csv file!", logger="Logs")
addPartitionQuery <- paste0("ALTER TABLE waf_noisyattack_clusters_", currentYearMonth, " ADD PARTITION (day=", currentDay, ")")

loginfo("Loading the partition of table waf_noisyattack_clusters_%s", currentYearMonth, logger="Logs")
d <- rhive.execute(addPartitionQuery)

loginfo("Loaded the partition in table!", logger="Logs")
rm(waf_noisyattack_localpath, waf_noisyattack_hdfspath)

loginfo("Flushing data to table waf_noisyattack_attacks_%s", currentYearMonth, logger="Logs")
waf_noisyattack_hdfspath <- paste0(hiveWarehousePath, tableNameOutput2, currentYearMonth)

loginfo("Giving all read and write permissions to path = %s", waf_noisyattack_hdfspath, logger="Logs")
d <- rhive.hdfs.chmod("777", waf_noisyattack_hdfspath, recursive=TRUE)

loginfo("all read and write permissions are given", logger="Logs")
waf_noisyattack_hdfspath <- paste0(hiveWarehousePath, tableNameOutput2, currentYearMonth, "/day=", currentDay)

loginfo("Creating partition at %s", waf_noisyattack_hdfspath, logger="Logs")
partitions <- rhive.hdfs.mkdirs(waf_noisyattack_hdfspath)

loginfo("Created partition!", logger="Logs")
waf_noisyattack_localpath <- paste0(rWorkingDir, "/waf_noisyattack_attacks.csv")

loginfo("Creating waf_noisyattack_attacks.csv file at path %s", waf_noisyattack_localpath, logger="Logs")
d <- write.table(outlierIPAttacks, file = waf_noisyattack_localpath, quote = FALSE, row.names=FALSE, sep = ",", col.names = FALSE)

loginfo("Created waf_noisyattack_attacks.csv file", logger="Logs")
loginfo("Copying waf_noisyattack_attacks.csv file data from local %s to hdfs %s", waf_noisyattack_localpath, waf_noisyattack_hdfspath, logger="Logs")
d <- rhive.hdfs.put(waf_noisyattack_localpath, waf_noisyattack_hdfspath, srcDel = TRUE, overwrite = TRUE)

loginfo("Copied the waf_noisyattack_attacks.csv file!", logger="Logs")
addPartitionQuery <- paste0("ALTER TABLE waf_noisyattack_attacks_", currentYearMonth, " ADD PARTITION (day=", currentDay, ")")

loginfo("Loading the partition of table waf_noisyattack_attacks_%s", currentYearMonth, logger="Logs")
d <- rhive.execute(addPartitionQuery)

loginfo("Loaded the partition in table!", logger="Logs")
rm(waf_noisyattack_localpath, waf_noisyattack_hdfspath)

loginfo("Flushing data to table waf_noisyattack_anomalousip_%s", currentYearMonth, logger="Logs")
waf_noisyattack_hdfspath <- paste0(hiveWarehousePath, tableNameOutput3, currentYearMonth)

loginfo("Giving all read and write permissions to path = %s", waf_noisyattack_hdfspath, logger="Logs")
d <- rhive.hdfs.chmod("777", waf_noisyattack_hdfspath, recursive=TRUE)

loginfo("all read and write permissions are given", logger="Logs")
waf_noisyattack_hdfspath <- paste0(hiveWarehousePath, tableNameOutput3, currentYearMonth, "/day=", currentDay)

loginfo("Creating partition at %s", waf_noisyattack_hdfspath, logger="Logs")
partitions <- rhive.hdfs.mkdirs(waf_noisyattack_hdfspath)

loginfo("Created partition!", logger="Logs")
waf_noisyattack_localpath <- paste0(rWorkingDir, "/waf_noisyattack_anomalousip.csv")

loginfo("Creating waf_noisyattack_anomalousip.csv file at path %s", waf_noisyattack_localpath, logger="Logs")
d <- write.table(anomalousIPList, file = waf_noisyattack_localpath, quote = FALSE, row.names=FALSE, sep = ",", col.names = FALSE)

loginfo("Created waf_noisyattack_anomalousip.csv file", logger="Logs")
loginfo("Copying waf_noisyattack_anomalousip.csv file data from local %s to hdfs %s", waf_noisyattack_localpath, waf_noisyattack_hdfspath, logger="Logs")
d <- rhive.hdfs.put(waf_noisyattack_localpath, waf_noisyattack_hdfspath, srcDel = TRUE, overwrite = TRUE)

loginfo("Copied the waf_noisyattack_anomalousip.csv file!", logger="Logs")
addPartitionQuery <- paste0("ALTER TABLE waf_noisyattack_anomalousip_", currentYearMonth, " ADD PARTITION (day=", currentDay, ")")

loginfo("Loading the partition of table waf_noisyattack_anomalousip_%s", currentYearMonth, logger="Logs")
d <- rhive.execute(addPartitionQuery)

loginfo("Loaded the partition in table!", logger="Logs")
status <- rhive.close()
rm(list = ls())
