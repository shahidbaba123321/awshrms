document.addEventListener('DOMContentLoaded', function() {
    const ctx1 = document.getElementById('performanceChart').getContext('2d');
    const performanceChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            datasets: [{
                label: 'Performance',
                data: [65, 59, 80, 81, 56, 55],
                borderColor: 'rgba(66, 133, 244, 1)',
                fill: false
            }]
        }
    });

    const ctx2 = document.getElementById('employeeChart').getContext('2d');
    const employeeChart = new Chart(ctx2, {
        type: 'doughnut',
        data: {
            labels: ['Engineering', 'HR', 'Sales', 'Marketing'],
            datasets: [{
                data: [12, 19, 3, 5],
                backgroundColor: [
                    'rgba(66, 133, 244, 0.6)',
                    'rgba(219, 68, 55, 0.6)',
                    'rgba(244, 180, 0, 0.6)',
                    'rgba(15, 157, 88, 0.6)'
                ]
            }]
        }
    });
});
