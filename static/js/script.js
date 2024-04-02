function updatePacketTable() {
  fetch('/get_latest_packets')
      .then(response => response.json())
      .then(data => {
          const packetTableBody = document.getElementById('packetTableBody');
          packetTableBody.innerHTML = ''; // Clear old data

          data.forEach(packet => {
              const row = document.createElement('tr');
              row.innerHTML = `
                  <td>${packet['No.']}</td>
                  <td>${packet['Time']}</td>
                  <td>${packet['Source']}</td>
                  <td>${packet['Destination']}</td>
                  <td>${packet['Protocol']}</td>
                  <td>${packet['Length']}</td>
                  <td>${packet['Info']}</td>
              `;
              packetTableBody.appendChild(row);
          });
      })
      .catch(error => {
          console.error('Error fetching data:', error);
      });
}

// Update every 5 seconds
setInterval(updatePacketTable, 5000);

// Initial update
updatePacketTable();