// Set new default font family and font color to mimic Bootstrap's default styling
Chart.defaults.global.defaultFontFamily = 'Nunito', '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
Chart.defaults.global.defaultFontColor = '#858796';

var temperature = document.getElementById('temperature');
var username = document.getElementById('username').value ;
var devicename = document.getElementById('deviceid').value ;

function getdevice(){
    var requests = $.get('/user/'+ username +'/deviceinfo/' + devicename);
    
    var tm = requests.done(function (result){
        var today = new Date();
        var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
        addData(temp_chart, time, result[3]);
        addData(humid_chart, time, result[4]);
        document.getElementById("card-temp").innerHTML = result[3] + "&deg;C";
        document.getElementById("card-humidity").innerHTML = result[4] + "%";
        if (couter >= 10 ){
            removeData(temp_chart);
            removeData(humid_chart);
        }
        couter++;

        setTimeout(getdevice, 2000);
        
    
    });
    
}

// Area Chart Example
var temp_chart = new Chart(temperature, {
  type: 'line',
  data: {
      labels: [],
      datasets: [{
          label: 'Temperature ℃',
          data: [],
          fill:true,
          lineTension: 0.3,
          backgroundColor: "rgba(78, 115, 223, 0.05)",
          borderColor: "rgba(78, 115, 223, 1)",
          pointRadius: 3,
          pointBackgroundColor: "rgba(78, 115, 223, 1)",
          pointBorderColor: "rgba(78, 115, 223, 1)",
          pointHoverRadius: 3,
          pointHoverBackgroundColor: "rgba(78, 115, 223, 1)",
          pointHoverBorderColor: "rgba(78, 115, 223, 1)",
          pointHitRadius: 10,
          pointBorderWidth: 2,
      }]
  },
  options: {
    maintainAspectRatio: false,
    layout: {
      padding: {
        left: 10,
        right: 25,
        top: 25,
        bottom: 0
      }
    },
      scales: {
          yAxes: [{
              ticks: {
                  beginAtZero: true
              }
          }]
      }
  }
});

var humidity = document.getElementById('humidity');
var humid_chart = new Chart(humidity, {
  type: 'line',
  data: {
      labels: [],
      datasets: [{
          label: 'Humidity ',
          data: [],
          fill:true,
          lineTension: 0.3,
          backgroundColor: "rgba(33, 150, 243, 0.1)",
          borderColor: "rgba(33, 150, 243, 1)",
          pointRadius: 3,
          pointBackgroundColor: "rgba(78, 115, 223, 1)",
          pointBorderColor: "rgba(78, 115, 223, 1)",
          pointHoverRadius: 3,
          pointHoverBackgroundColor: "rgba(78, 115, 223, 1)",
          pointHoverBorderColor: "rgba(78, 115, 223, 1)",
          pointHitRadius: 10,
          pointBorderWidth: 2,
      }]
  },
  options: {
    maintainAspectRatio: false,
    layout: {
      padding: {
        left: 10,
        right: 25,
        top: 25,
        bottom: 0
      }
    },
      scales: {
          yAxes: [{
              ticks: {
                  beginAtZero: true
              }
          }]
      }
  }
});


function addData(chart, label, data) {
  chart.data.labels.push(label);
  chart.data.datasets.forEach((dataset) => {
      dataset.data.push(data);
  });
  chart.update();
}

function removeData(chart) {
  chart.data.labels.shift();
  chart.data.datasets.forEach((dataset) => {
      dataset.data.shift();
  });
  chart.update();
}
var couter = 0; 

getdevice();
